/*	$OpenBSD: if_awg.c,v 1.1 2026/09/24 00:00:00 truebad0ur Exp $ */

/*
 * Copyright (C) 2026 Andrey Orekhov <pieceofcakecupofcoffee@gmail.com>
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>
 *
 * AmneziaWG kernel driver for OpenBSD.
 * Based on if_wg.c (WireGuard driver) from OpenBSD src/sys/net/.
 * Adds obfuscation parameters: Jc, Jmin, Jmax, S1, S2, H1-H4 (legacy) and
 * the AmneziaWG 3.1 set: S3, S4, H1-H4 ranges, I1-I5, HeaderProtectionKey,
 * ContentPaddingAddition, timings, RandomTrailers, DisableCookies.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "bpfilter.h"
#include "pf.h"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/pool.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/percpu.h>
#include <sys/ioctl.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/smr.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_awg.h>

#include <net/awg_noise.h>
#include <net/wg_cookie.h>

#include <net/pfvar.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/art.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/in_pcb.h>

#include <crypto/siphash.h>
#include <crypto/chacha_private.h>

#define DEFAULT_MTU		1420

#define MAX_STAGED_PKT		128
#define MAX_QUEUED_PKT		1024
#define MAX_QUEUED_PKT_MASK	(MAX_QUEUED_PKT - 1)

#define MAX_QUEUED_HANDSHAKES	4096

#define HASHTABLE_PEER_SIZE	(1 << 11)
#define HASHTABLE_INDEX_SIZE	(1 << 13)
#define MAX_PEERS_PER_IFACE	(1 << 20)

#define REKEY_TIMEOUT		5
#define REKEY_TIMEOUT_JITTER	334 /* 1/3 sec, round for arc4random_uniform */
#define KEEPALIVE_TIMEOUT	10
#define MAX_TIMER_HANDSHAKES	(90 / REKEY_TIMEOUT)
#define UNDERLOAD_TIMEOUT	1

#define AWG_DEFAULT_UDP_WINDOW	500	/* initial peer UDP window, 3.1 */
#define AWG_MAX_UDP_PAYLOAD	65507

#define AWGPRINTF(loglevel, sc, mtx, fmt, ...) do {		\
	if (ISSET((sc)->sc_if.if_flags, IFF_DEBUG)) {		\
		if (mtx)					\
			mtx_enter(mtx);				\
		log(loglevel, "%s: " fmt, (sc)->sc_if.if_xname, \
		    ##__VA_ARGS__);				\
		if (mtx)					\
			mtx_leave(mtx);				\
	}							\
} while (0)

#define CONTAINER_OF(ptr, type, member) ({			\
	const __typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define AWG_PKT_WITH_PADDING(n)	(((n) + (16-1)) & (~(16-1)))
#define AWG_KEY_SIZE		AWG_KEY_LEN

/* Smallest transport message: header + auth tag of empty payload */
#define AWG_MIN_DATA_SIZE	(sizeof(struct awg_pkt_data) + NOISE_AUTHTAG_LEN)

struct awg_pkt_initiation {
	uint32_t		t;
	uint32_t		s_idx;
	uint8_t			ue[NOISE_PUBLIC_KEY_LEN];
	uint8_t			es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN];
	uint8_t			ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN];
	struct cookie_macs	m;
};

struct awg_pkt_response {
	uint32_t		t;
	uint32_t		s_idx;
	uint32_t		r_idx;
	uint8_t			ue[NOISE_PUBLIC_KEY_LEN];
	uint8_t			en[0 + NOISE_AUTHTAG_LEN];
	struct cookie_macs	m;
};

struct awg_pkt_cookie {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[COOKIE_NONCE_SIZE];
	uint8_t			ec[COOKIE_ENCRYPTED_SIZE];
};

struct awg_pkt_data {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[sizeof(uint64_t)];
	uint8_t			buf[];
};

struct awg_endpoint {
	union {
		struct sockaddr		r_sa;
		struct sockaddr_in	r_sin;
#ifdef INET6
		struct sockaddr_in6	r_sin6;
#endif
	} e_remote;
	union {
		struct in_addr		l_in;
#ifdef INET6
		struct in6_pktinfo	l_pktinfo6;
#define l_in6 l_pktinfo6.ipi6_addr
#endif
	} e_local;
};

struct awg_tag {
	struct awg_endpoint	 t_endpoint;
	struct awg_peer		*t_peer;
	struct mbuf		*t_mbuf;
	int			 t_done;
	int			 t_mtu;
	int			 t_type;	/* AWG_TYPE_*, set by awg_input */
};

/* Message types, decoded from the H1-H4 ranges */
#define AWG_TYPE_INITIATION	1
#define AWG_TYPE_RESPONSE	2
#define AWG_TYPE_COOKIE		3
#define AWG_TYPE_DATA		4

/* I1-I5 packet: static bytes with regions rewritten on each send */
#define AWG_ISPEC_MOD_COUNTER	1	/* <c> */
#define AWG_ISPEC_MOD_TIME	2	/* <t> */
#define AWG_ISPEC_MOD_RAND	3	/* <r N> */
#define AWG_ISPEC_MOD_CHARS	4	/* <rc N> */
#define AWG_ISPEC_MOD_DIGITS	5	/* <rd N> */

struct awg_ispec_mod {
	int			 im_type;
	size_t			 im_off;
	size_t			 im_len;
};

struct awg_ispec {
	char			*is_desc;	/* tag string as configured */
	size_t			 is_desc_size;
	uint8_t			*is_pkt;
	size_t			 is_pkt_len;
	struct awg_ispec_mod	*is_mods;
	size_t			 is_mods_count;
};

struct awg_index {
	LIST_ENTRY(awg_index)	 i_entry;
	SLIST_ENTRY(awg_index)	 i_unused_entry;
	uint32_t		 i_key;
	struct awg_noise_remote	*i_value;
};

struct awg_timers {
	/* t_mtx is for blocking awg_timers_event_* when setting t_disabled. */
	struct mutex		 t_mtx;

	int			 t_disabled;
	int			 t_need_another_keepalive;
	uint16_t		 t_persistent_keepalive_interval;
	uint16_t		 t_persistent_keepalive_hi;	/* range, 3.1 */
	struct timeout		 t_new_handshake;
	struct timeout		 t_send_keepalive;
	struct timeout		 t_retry_handshake;
	struct timeout		 t_zero_key_material;
	struct timeout		 t_persistent_keepalive;

	struct mutex		 t_handshake_mtx;
	struct timespec		 t_handshake_last_sent;	/* nanouptime */
	struct timespec		 t_handshake_complete;	/* nanotime */
	int			 t_handshake_retries;
	int			 t_max_handshake_retries;
};

struct awg_aip {
	struct art_node		 a_node;
	LIST_ENTRY(awg_aip)	 a_entry;
	struct awg_peer		*a_peer;
	struct awg_aip_io	 a_data;
};

struct awg_queue {
	struct mutex		 q_mtx;
	struct mbuf_list	 q_list;
};

struct awg_ring {
	struct mutex	 r_mtx;
	uint32_t	 r_head;
	uint32_t	 r_tail;
	struct mbuf	*r_buf[MAX_QUEUED_PKT];
};

struct awg_peer {
	LIST_ENTRY(awg_peer)	 p_pubkey_entry;
	TAILQ_ENTRY(awg_peer)	 p_seq_entry;
	uint64_t		 p_id;
	struct awg_softc		*p_sc;

	struct awg_noise_remote	 p_remote;
	struct cookie_maker	 p_cookie;
	struct awg_timers	 p_timers;

	struct mutex		 p_counters_mtx;
	uint64_t		 p_counters_tx;
	uint64_t		 p_counters_rx;

	struct mutex		 p_endpoint_mtx;
	struct awg_endpoint	 p_endpoint;
	uint32_t		 p_udp_window;	/* largest datagram seen, 3.1 */

	struct task		 p_send_initiation;
	struct task		 p_send_keepalive;
	struct task		 p_clear_secrets;
	struct task		 p_deliver_out;
	struct task		 p_deliver_in;

	struct mbuf_queue	 p_stage_queue;
	struct awg_queue		 p_encap_queue;
	struct awg_queue		 p_decap_queue;

	SLIST_HEAD(,awg_index)	 p_unused_index;
	struct awg_index		 p_index[3];

	LIST_HEAD(,awg_aip)	 p_aip;

	SLIST_ENTRY(awg_peer)	 p_start_list;
	int			 p_start_onlist;

	char			 p_description[IFDESCRSIZE];
};

struct awg_softc {
	struct ifnet		 sc_if;
	SIPHASH_KEY		 sc_secret;

	struct rwlock		 sc_lock;
	struct awg_noise_local	 sc_local;
	struct cookie_checker	 sc_cookie;
	in_port_t		 sc_udp_port;
	int			 sc_udp_rtable;

	struct rwlock		 sc_so_lock;
	struct socket		*sc_so4;
#ifdef INET6
	struct socket		*sc_so6;
#endif

	struct rwlock		 sc_aip_lock;
	size_t			 sc_aip_num;
	struct art		*sc_aip4;
#ifdef INET6
	struct art		*sc_aip6;
#endif

	struct rwlock		 sc_peer_lock;
	size_t			 sc_peer_num;
	LIST_HEAD(,awg_peer)	*sc_peer;
	TAILQ_HEAD(,awg_peer)	 sc_peer_seq;
	u_long			 sc_peer_mask;

	struct mutex		 sc_index_mtx;
	LIST_HEAD(,awg_index)	*sc_index;
	u_long			 sc_index_mask;

	struct task		 sc_handshake;
	struct mbuf_queue	 sc_handshake_queue;

	struct task		 sc_encap;
	struct task		 sc_decap;
	struct awg_ring		 sc_encap_ring;
	struct awg_ring		 sc_decap_ring;

	/*
	 * AmneziaWG obfuscation parameters (defaults = standard WireGuard).
	 * Written under sc_lock, read without locking by the packet path;
	 * a packet racing a reconfiguration may be dropped.
	 */
	int			 sc_awg_version;	/* AWG_VERSION_* */
	uint16_t		 sc_awg_jc;
	uint16_t		 sc_awg_jmin;
	uint16_t		 sc_awg_jmax;
	uint16_t		 sc_awg_s1;
	uint16_t		 sc_awg_s2;
	uint16_t		 sc_awg_s3;
	uint16_t		 sc_awg_s4;
	struct awg_range	 sc_awg_h1;
	struct awg_range	 sc_awg_h2;
	struct awg_range	 sc_awg_h3;
	struct awg_range	 sc_awg_h4;
	int			 sc_awg_has_hpk;
	uint8_t			 sc_awg_hpk[AWG_HPK_LEN];
	struct awg_range	 sc_awg_cpa;
	struct awg_range	 sc_awg_rekey_after_time;
	struct awg_range	 sc_awg_rekey_timeout;
	struct awg_range	 sc_awg_reject_after_time;
	struct awg_range	 sc_awg_keepalive_timeout;
	struct awg_range	 sc_awg_max_handshake_attempts;
	int			 sc_awg_random_trailers;
	int			 sc_awg_disable_cookies;

	struct rwlock		 sc_ispec_lock;
	struct awg_ispec	 sc_awg_ispec[AWG_ISPEC_COUNT];
};

struct awg_peer *
	awg_peer_create(struct awg_softc *, uint8_t[AWG_KEY_SIZE]);
struct awg_peer *
	awg_peer_lookup(struct awg_softc *, const uint8_t[AWG_KEY_SIZE]);
void	awg_peer_destroy(struct awg_peer *);
void	awg_peer_set_endpoint_from_tag(struct awg_peer *, struct awg_tag *);
void	awg_peer_set_sockaddr(struct awg_peer *, struct sockaddr *);
int	awg_peer_get_sockaddr(struct awg_peer *, struct sockaddr *);
void	awg_peer_clear_src(struct awg_peer *);
void	awg_peer_get_endpoint(struct awg_peer *, struct awg_endpoint *);
void	awg_peer_counters_add(struct awg_peer *, uint64_t, uint64_t);

int	awg_aip_add(struct awg_softc *, struct awg_peer *, struct awg_aip_io *);
struct awg_peer *
	awg_aip_lookup(struct art *, void *);
int	awg_aip_remove(struct awg_softc *, struct awg_peer *,
	    struct awg_aip_io *);

int	awg_socket_open(struct socket **, int, in_port_t *, int *, void *);
void	awg_socket_close(struct socket **);
int	awg_bind(struct awg_softc *, in_port_t *, int *);
void	awg_unbind(struct awg_softc *);
int	awg_send(struct awg_softc *, struct awg_endpoint *, struct mbuf *);
void	awg_send_buf(struct awg_softc *, struct awg_endpoint *, uint8_t *,
	    size_t);

struct awg_tag *
	awg_tag_get(struct mbuf *);

void	awg_timers_init(struct awg_timers *);
void	awg_timers_enable(struct awg_timers *);
void	awg_timers_disable(struct awg_timers *);
void	awg_timers_set_persistent_keepalive(struct awg_timers *, uint16_t,
	    uint16_t);
int	awg_timers_get_persistent_keepalive(struct awg_timers *, uint16_t *,
	    uint16_t *);
void	awg_timers_get_last_handshake(struct awg_timers *, struct timespec *);
int	awg_timers_expired_handshake_last_sent(struct awg_timers *);
int	awg_timers_check_handshake_last_sent(struct awg_timers *);

void	awg_timers_event_data_sent(struct awg_timers *);
void	awg_timers_event_data_received(struct awg_timers *);
void	awg_timers_event_any_authenticated_packet_sent(struct awg_timers *);
void	awg_timers_event_any_authenticated_packet_received(struct awg_timers *);
void	awg_timers_event_handshake_initiated(struct awg_timers *);
void	awg_timers_event_handshake_responded(struct awg_timers *);
void	awg_timers_event_handshake_complete(struct awg_timers *);
void	awg_timers_event_session_derived(struct awg_timers *);
void	awg_timers_event_any_authenticated_packet_traversal(struct awg_timers *);
void	awg_timers_event_want_initiation(struct awg_timers *);
void	awg_timers_event_reset_handshake_last_sent(struct awg_timers *);

void	awg_timers_run_send_initiation(void *, int);
void	awg_timers_run_retry_handshake(void *);
void	awg_timers_run_send_keepalive(void *);
void	awg_timers_run_new_handshake(void *);
void	awg_timers_run_zero_key_material(void *);
void	awg_timers_run_persistent_keepalive(void *);

uint32_t
	awg_range_pick(struct awg_range);
int	awg_range_contains(struct awg_range, uint32_t);
int	awg_range_is_zero(struct awg_range);
int	awg_range_overlap(struct awg_range, struct awg_range);
int	awg_rekey_timeout(struct awg_softc *);
int	awg_rekey_min_timeout(struct awg_softc *);
int	awg_keepalive_timeout(struct awg_softc *);
int	awg_new_handshake_timeout(struct awg_softc *);
int	awg_keychain_expire_time(struct awg_softc *);
int	awg_max_handshake_attempts(struct awg_softc *);
void	awg_update_noise_timings(struct awg_softc *);

int	awg_hp_init(struct awg_softc *, chacha_ctx *,
	    const uint8_t[AWG_HPK_NONCE_LEN]);
size_t	awg_random_trailer(struct awg_softc *, uint32_t, size_t);
size_t	awg_content_padding(struct awg_softc *, uint32_t, size_t);
void	awg_peer_update_udp_window(struct awg_peer *, uint32_t);

static int
	awg_hexval(int);
int	awg_ispec_parse(struct awg_ispec *, const char *);
void	awg_ispec_free(struct awg_ispec *);
void	awg_send_ispecs(struct awg_softc *, struct awg_peer *);

void	awg_peer_send_buf(struct awg_peer *, uint8_t *, size_t);
void	awg_send_hs(struct awg_softc *, struct awg_peer *,
	    struct awg_endpoint *, void *, size_t, uint16_t);
void	awg_send_junk(struct awg_softc *, struct awg_peer *);
void	awg_send_initiation(void *);
void	awg_send_response(struct awg_peer *);
void	awg_send_cookie(struct awg_softc *, struct cookie_macs *, uint32_t,
	    struct awg_endpoint *);
void	awg_send_keepalive(void *);
void	awg_peer_clear_secrets(void *);
void	awg_handshake(struct awg_softc *, struct mbuf *);
void	awg_handshake_worker(void *);

void	awg_encap(struct awg_softc *, struct mbuf *);
void	awg_decap(struct awg_softc *, struct mbuf *);
void	awg_encap_worker(void *);
void	awg_decap_worker(void *);
void	awg_deliver_out(void *);
void	awg_deliver_in(void *);

int	awg_queue_in(struct awg_softc *, struct awg_peer *, struct mbuf *);
void	awg_queue_out(struct awg_softc *, struct awg_peer *);
struct mbuf *
	awg_ring_dequeue(struct awg_ring *);
struct mbuf *
	awg_queue_dequeue(struct awg_queue *, struct awg_tag **);

struct awg_noise_remote *
	awg_remote_get(void *, uint8_t[NOISE_PUBLIC_KEY_LEN]);
uint32_t
	awg_index_set(void *, struct awg_noise_remote *);
struct awg_noise_remote *
	awg_index_get(void *, uint32_t);
void	awg_index_drop(void *, uint32_t);

int	awg_classify(struct awg_softc *, struct mbuf *, size_t *, size_t *,
	    uint8_t[AWG_HPK_NONCE_LEN], int *);
struct mbuf *
	awg_input(void *, struct mbuf *, struct ip *, struct ip6_hdr *, void *,
	    int, struct netstack *);
int	awg_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
int	awg_ioctl_check(struct awg_softc *, struct awg_interface_io *);
void	awg_reset_3_1(struct awg_softc *, struct awg_ispec[AWG_ISPEC_COUNT]);
int	awg_ioctl_set(struct awg_softc *, struct awg_data_io *);
int	awg_ioctl_get(struct awg_softc *, struct awg_data_io *);
int	awg_ioctl(struct ifnet *, u_long, caddr_t);
int	awg_up(struct awg_softc *);
void	awg_down(struct awg_softc *);

int	awg_clone_create(struct if_clone *, int);
int	awg_clone_destroy(struct ifnet *);
void	awgattach(int);

uint64_t	awg_peer_counter = 0;
struct pool	awg_aip_pool;
struct pool	awg_peer_pool;
struct pool	awg_ratelimit_pool;
struct timeval	awg_underload_interval = { UNDERLOAD_TIMEOUT, 0 };

size_t		 awg_counter = 0;
struct taskq	*awg_handshake_taskq;
struct taskq	*awg_crypt_taskq;

struct if_clone	awg_cloner =
    IF_CLONE_INITIALIZER("awg", awg_clone_create, awg_clone_destroy);

struct awg_peer *
awg_peer_create(struct awg_softc *sc, uint8_t public[AWG_KEY_SIZE])
{
	struct awg_peer	*peer;
	uint64_t	 idx;

	rw_assert_wrlock(&sc->sc_lock);

	if (sc->sc_peer_num >= MAX_PEERS_PER_IFACE)
		return NULL;

	if ((peer = pool_get(&awg_peer_pool, PR_NOWAIT)) == NULL)
		return NULL;

	peer->p_id = awg_peer_counter++;
	peer->p_sc = sc;

	awg_noise_remote_init(&peer->p_remote, public, &sc->sc_local);
	cookie_maker_init(&peer->p_cookie, public);
	awg_timers_init(&peer->p_timers);

	mtx_init(&peer->p_counters_mtx, IPL_NET);
	peer->p_counters_tx = 0;
	peer->p_counters_rx = 0;

	strlcpy(peer->p_description, "", IFDESCRSIZE);

	mtx_init(&peer->p_endpoint_mtx, IPL_NET);
	bzero(&peer->p_endpoint, sizeof(peer->p_endpoint));
	peer->p_udp_window = AWG_DEFAULT_UDP_WINDOW;

	task_set(&peer->p_send_initiation, awg_send_initiation, peer);
	task_set(&peer->p_send_keepalive, awg_send_keepalive, peer);
	task_set(&peer->p_clear_secrets, awg_peer_clear_secrets, peer);
	task_set(&peer->p_deliver_out, awg_deliver_out, peer);
	task_set(&peer->p_deliver_in, awg_deliver_in, peer);

	mq_init(&peer->p_stage_queue, MAX_STAGED_PKT, IPL_NET);
	mtx_init(&peer->p_encap_queue.q_mtx, IPL_NET);
	ml_init(&peer->p_encap_queue.q_list);
	mtx_init(&peer->p_decap_queue.q_mtx, IPL_NET);
	ml_init(&peer->p_decap_queue.q_list);

	SLIST_INIT(&peer->p_unused_index);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[0],
	    i_unused_entry);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[1],
	    i_unused_entry);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[2],
	    i_unused_entry);

	LIST_INIT(&peer->p_aip);

	peer->p_start_onlist = 0;

	idx = SipHash24(&sc->sc_secret, public, AWG_KEY_SIZE);
	idx &= sc->sc_peer_mask;

	rw_enter_write(&sc->sc_peer_lock);
	LIST_INSERT_HEAD(&sc->sc_peer[idx], peer, p_pubkey_entry);
	TAILQ_INSERT_TAIL(&sc->sc_peer_seq, peer, p_seq_entry);
	sc->sc_peer_num++;
	rw_exit_write(&sc->sc_peer_lock);

	AWGPRINTF(LOG_INFO, sc, NULL, "Peer %llu created\n", peer->p_id);
	return peer;
}

struct awg_peer *
awg_peer_lookup(struct awg_softc *sc, const uint8_t public[AWG_KEY_SIZE])
{
	uint8_t		 peer_key[AWG_KEY_SIZE];
	struct awg_peer	*peer;
	uint64_t	 idx;

	idx = SipHash24(&sc->sc_secret, public, AWG_KEY_SIZE);
	idx &= sc->sc_peer_mask;

	rw_enter_read(&sc->sc_peer_lock);
	LIST_FOREACH(peer, &sc->sc_peer[idx], p_pubkey_entry) {
		awg_noise_remote_keys(&peer->p_remote, peer_key, NULL);
		if (timingsafe_bcmp(peer_key, public, AWG_KEY_SIZE) == 0)
			goto done;
	}
	peer = NULL;
done:
	rw_exit_read(&sc->sc_peer_lock);
	return peer;
}

void
awg_peer_destroy(struct awg_peer *peer)
{
	struct awg_softc	*sc = peer->p_sc;
	struct awg_aip *aip, *taip;

	rw_assert_wrlock(&sc->sc_lock);

	/*
	 * Remove peer from the pubkey hashtable and disable all timeouts.
	 * After this, and flushing awg_handshake_taskq, then no more handshakes
	 * can be started.
	 */
	rw_enter_write(&sc->sc_peer_lock);
	LIST_REMOVE(peer, p_pubkey_entry);
	TAILQ_REMOVE(&sc->sc_peer_seq, peer, p_seq_entry);
	sc->sc_peer_num--;
	rw_exit_write(&sc->sc_peer_lock);

	awg_timers_disable(&peer->p_timers);

	taskq_barrier(awg_handshake_taskq);

	/*
	 * Now we drop all allowed ips, to drop all outgoing packets to the
	 * peer. Then drop all the indexes to drop all incoming packets to the
	 * peer. Then we can flush if_snd, awg_crypt_taskq and then nettq to
	 * ensure no more references to the peer exist.
	 */
	LIST_FOREACH_SAFE(aip, &peer->p_aip, a_entry, taip)
		awg_aip_remove(sc, peer, &aip->a_data);

	awg_noise_remote_clear(&peer->p_remote);

	NET_LOCK();
	while (!ifq_empty(&sc->sc_if.if_snd)) {
		/*
		 * XXX: `if_snd' of stopped interface could still
		 * contain packets
		 */
		if (!ISSET(sc->sc_if.if_flags, IFF_RUNNING)) {
			ifq_purge(&sc->sc_if.if_snd);
			continue;
		}
		NET_UNLOCK();
		tsleep_nsec(&nowake, PWAIT, "awg_ifq", 1000);
		NET_LOCK();
	}
	NET_UNLOCK();

	taskq_barrier(awg_crypt_taskq);
	taskq_barrier(net_tq(sc->sc_if.if_index));

	if (!mq_empty(&peer->p_stage_queue))
		mq_purge(&peer->p_stage_queue);

	AWGPRINTF(LOG_INFO, sc, NULL, "Peer %llu destroyed\n", peer->p_id);
	explicit_bzero(peer, sizeof(*peer));
	pool_put(&awg_peer_pool, peer);
}

void
awg_peer_set_endpoint_from_tag(struct awg_peer *peer, struct awg_tag *t)
{
	if (memcmp(&t->t_endpoint, &peer->p_endpoint,
	    sizeof(t->t_endpoint)) == 0)
		return;

	mtx_enter(&peer->p_endpoint_mtx);
	peer->p_endpoint = t->t_endpoint;
	peer->p_udp_window = AWG_DEFAULT_UDP_WINDOW;
	mtx_leave(&peer->p_endpoint_mtx);
}

void
awg_peer_set_sockaddr(struct awg_peer *peer, struct sockaddr *remote)
{
	mtx_enter(&peer->p_endpoint_mtx);
	memcpy(&peer->p_endpoint.e_remote, remote,
	       sizeof(peer->p_endpoint.e_remote));
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	peer->p_udp_window = AWG_DEFAULT_UDP_WINDOW;
	mtx_leave(&peer->p_endpoint_mtx);
}

int
awg_peer_get_sockaddr(struct awg_peer *peer, struct sockaddr *remote)
{
	int	ret = 0;

	mtx_enter(&peer->p_endpoint_mtx);
	if (peer->p_endpoint.e_remote.r_sa.sa_family != AF_UNSPEC)
		memcpy(remote, &peer->p_endpoint.e_remote,
		       sizeof(peer->p_endpoint.e_remote));
	else
		ret = ENOENT;
	mtx_leave(&peer->p_endpoint_mtx);
	return ret;
}

void
awg_peer_clear_src(struct awg_peer *peer)
{
	mtx_enter(&peer->p_endpoint_mtx);
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	mtx_leave(&peer->p_endpoint_mtx);
}

void
awg_peer_get_endpoint(struct awg_peer *peer, struct awg_endpoint *endpoint)
{
	mtx_enter(&peer->p_endpoint_mtx);
	memcpy(endpoint, &peer->p_endpoint, sizeof(*endpoint));
	mtx_leave(&peer->p_endpoint_mtx);
}

void
awg_peer_counters_add(struct awg_peer *peer, uint64_t tx, uint64_t rx)
{
	mtx_enter(&peer->p_counters_mtx);
	peer->p_counters_tx += tx;
	peer->p_counters_rx += rx;
	mtx_leave(&peer->p_counters_mtx);
}

int
awg_aip_add(struct awg_softc *sc, struct awg_peer *peer, struct awg_aip_io *d)
{
	struct art	*root;
	struct art_node	*node;
	struct awg_aip	*aip;
	int		 ret = 0;

	switch (d->a_af) {
	case AF_INET:
		root = sc->sc_aip4;
		break;
#ifdef INET6
	case AF_INET6:
		root = sc->sc_aip6;
		break;
#endif
	default:
		return EAFNOSUPPORT;
	}

	if (d->a_cidr > root->art_alen)
		return EINVAL;

	if ((aip = pool_get(&awg_aip_pool, PR_NOWAIT|PR_ZERO)) == NULL)
		return ENOBUFS;

	art_node_init(&aip->a_node, &d->a_addr.addr_bytes, d->a_cidr);

	rw_enter_write(&sc->sc_aip_lock);
	node = art_insert(root, &aip->a_node);

	if (node == &aip->a_node) {
		aip->a_peer = peer;
		aip->a_data = *d;
		LIST_INSERT_HEAD(&peer->p_aip, aip, a_entry);
		sc->sc_aip_num++;
	} else {
		pool_put(&awg_aip_pool, aip);
		aip = (struct awg_aip *) node;
		if (aip->a_peer != peer) {
			LIST_REMOVE(aip, a_entry);
			LIST_INSERT_HEAD(&peer->p_aip, aip, a_entry);
			aip->a_peer = peer;
		}
	}
	rw_exit_write(&sc->sc_aip_lock);
	return ret;
}

struct awg_peer *
awg_aip_lookup(struct art *root, void *addr)
{
	struct art_node	*node;

	smr_read_enter();
	node = art_match(root, addr);
	smr_read_leave();

	return node == NULL ? NULL : ((struct awg_aip *) node)->a_peer;
}

int
awg_aip_remove(struct awg_softc *sc, struct awg_peer *peer, struct awg_aip_io *d)
{
	struct art	*root;
	struct art_node	*node;
	struct awg_aip	*aip;
	int		 ret = 0;

	switch (d->a_af) {
	case AF_INET:
		root = sc->sc_aip4;
		break;
#ifdef INET6
	case AF_INET6:
		root = sc->sc_aip6;
		break;
#endif
	default:
		return EAFNOSUPPORT;
	}

	rw_enter_write(&sc->sc_aip_lock);
	smr_read_enter();
	node = art_lookup(root, &d->a_addr, d->a_cidr);
	smr_read_leave();
	if (node == NULL) {
		ret = ENOENT;
	} else if (((struct awg_aip *) node)->a_peer != peer) {
		ret = EXDEV;
	} else {
		aip = (struct awg_aip *)node;
		if (art_delete(root, &d->a_addr, d->a_cidr) == NULL)
			panic("art_delete failed to delete node %p", node);

		sc->sc_aip_num--;
		LIST_REMOVE(aip, a_entry);
		pool_put(&awg_aip_pool, aip);
	}
	rw_exit_write(&sc->sc_aip_lock);
	return ret;
}

int
awg_socket_open(struct socket **so, int af, in_port_t *port,
    int *rtable, void *upcall_arg)
{
	struct mbuf		 mhostnam, mrtable;
#ifdef INET6
	struct sockaddr_in6	*sin6;
#endif
	struct sockaddr_in	*sin;
	int			 ret;

	m_inithdr(&mhostnam);
	m_inithdr(&mrtable);

	bzero(mtod(&mrtable, u_int *), sizeof(u_int));
	*mtod(&mrtable, u_int *) = *rtable;
	mrtable.m_len = sizeof(u_int);

	if (af == AF_INET) {
		sin = mtod(&mhostnam, struct sockaddr_in *);
		bzero(sin, sizeof(*sin));
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_port = *port;
		sin->sin_addr.s_addr = INADDR_ANY;
		mhostnam.m_len = sin->sin_len;
#ifdef INET6
	} else if (af == AF_INET6) {
		sin6 = mtod(&mhostnam, struct sockaddr_in6 *);
		bzero(sin6, sizeof(*sin6));
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = *port;
		sin6->sin6_addr = (struct in6_addr) { .s6_addr = { 0 } };
		mhostnam.m_len = sin6->sin6_len;
#endif
	} else {
		return EAFNOSUPPORT;
	}

	if ((ret = socreate(af, so, SOCK_DGRAM, 0)) != 0)
		return ret;

	solock(*so);
	sotoinpcb(*so)->inp_upcall = awg_input;
	sotoinpcb(*so)->inp_upcall_arg = upcall_arg;
	sounlock(*so);

	if ((ret = sosetopt(*so, SOL_SOCKET, SO_RTABLE, &mrtable)) == 0) {
		solock(*so);
		if ((ret = sobind(*so, &mhostnam, curproc)) == 0) {
			*port = sotoinpcb(*so)->inp_lport;
			*rtable = sotoinpcb(*so)->inp_rtableid;
		}
		sounlock(*so);
	}

	if (ret != 0)
		awg_socket_close(so);

	return ret;
}

void
awg_socket_close(struct socket **so)
{
	if (*so != NULL && soclose(*so, 0) != 0)
		panic("Unable to close awg socket");
	*so = NULL;
}

int
awg_bind(struct awg_softc *sc, in_port_t *portp, int *rtablep)
{
	int		 ret = 0, rtable = *rtablep;
	in_port_t	 port = *portp;
	struct socket	*so4;
#ifdef INET6
	struct socket	*so6;
	int		 retries = 0;
retry:
#endif
	if ((ret = awg_socket_open(&so4, AF_INET, &port, &rtable, sc)) != 0)
		return ret;

#ifdef INET6
	if ((ret = awg_socket_open(&so6, AF_INET6, &port, &rtable, sc)) != 0) {
		if (ret == EADDRINUSE && *portp == 0 && retries++ < 100)
			goto retry;
		awg_socket_close(&so4);
		return ret;
	}
#endif

	rw_enter_write(&sc->sc_so_lock);
	awg_socket_close(&sc->sc_so4);
	sc->sc_so4 = so4;
#ifdef INET6
	awg_socket_close(&sc->sc_so6);
	sc->sc_so6 = so6;
#endif
	rw_exit_write(&sc->sc_so_lock);

	*portp = port;
	*rtablep = rtable;
	return 0;
}

void
awg_unbind(struct awg_softc *sc)
{
	rw_enter_write(&sc->sc_so_lock);
	awg_socket_close(&sc->sc_so4);
#ifdef INET6
	awg_socket_close(&sc->sc_so6);
#endif
	rw_exit_write(&sc->sc_so_lock);
}

int
awg_send(struct awg_softc *sc, struct awg_endpoint *e, struct mbuf *m)
{
	struct mbuf	 peernam, *control = NULL;
	int		 ret;

	/* Get local control address before locking */
	if (e->e_remote.r_sa.sa_family == AF_INET) {
		if (e->e_local.l_in.s_addr != INADDR_ANY)
			control = sbcreatecontrol(&e->e_local.l_in,
			    sizeof(struct in_addr), IP_SENDSRCADDR,
			    IPPROTO_IP);
#ifdef INET6
	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&e->e_local.l_in6))
			control = sbcreatecontrol(&e->e_local.l_pktinfo6,
			    sizeof(struct in6_pktinfo), IPV6_PKTINFO,
			    IPPROTO_IPV6);
#endif
	} else {
		m_freem(m);
		return EAFNOSUPPORT;
	}

	/* Get remote address */
	peernam.m_type = MT_SONAME;
	peernam.m_next = NULL;
	peernam.m_nextpkt = NULL;
	peernam.m_data = (void *)&e->e_remote.r_sa;
	peernam.m_len = e->e_remote.r_sa.sa_len;
	peernam.m_flags = 0;

	rw_enter_read(&sc->sc_so_lock);
	if (e->e_remote.r_sa.sa_family == AF_INET && sc->sc_so4 != NULL)
		ret = sosend(sc->sc_so4, &peernam, NULL, m, control, 0);
#ifdef INET6
	else if (e->e_remote.r_sa.sa_family == AF_INET6 && sc->sc_so6 != NULL)
		ret = sosend(sc->sc_so6, &peernam, NULL, m, control, 0);
#endif
	else {
		ret = ENOTCONN;
		m_freem(control);
		m_freem(m);
	}
	rw_exit_read(&sc->sc_so_lock);

	return ret;
}

void
awg_send_buf(struct awg_softc *sc, struct awg_endpoint *e, uint8_t *buf,
    size_t len)
{
	struct mbuf	*m;
	int		 ret = 0;
	size_t		 mlen = len + max_hdr;

retry:
	m = m_gethdr(M_WAIT, MT_DATA);
	if (mlen > MHLEN)
		MCLGETL(m, M_WAIT, mlen);
	m_align(m, len);
	m->m_pkthdr.len = m->m_len = len;
	memcpy(mtod(m, void *), buf, len);

	/* As we're sending a handshake packet here, we want high priority */
	m->m_pkthdr.pf.prio = IFQ_MAXPRIO;

	if (ret == 0) {
		ret = awg_send(sc, e, m);
		/* Retry if we couldn't bind to e->e_local */
		if (ret == EADDRNOTAVAIL) {
			bzero(&e->e_local, sizeof(e->e_local));
			goto retry;
		}
	} else {
		ret = awg_send(sc, e, m);
		if (ret != 0)
			AWGPRINTF(LOG_DEBUG, sc, NULL,
			    "Unable to send packet\n");
	}
}

struct awg_tag *
awg_tag_get(struct mbuf *m)
{
	struct m_tag	*mtag;

	if ((mtag = m_tag_find(m, PACKET_TAG_WIREGUARD, NULL)) == NULL) {
		mtag = m_tag_get(PACKET_TAG_WIREGUARD, sizeof(struct awg_tag),
		    M_NOWAIT);
		if (mtag == NULL)
			return (NULL);
		bzero(mtag + 1, sizeof(struct awg_tag));
		m_tag_prepend(m, mtag);
	}
	return ((struct awg_tag *)(mtag + 1));
}

/*
 * AmneziaWG helpers. Ranges are inclusive; the timing ranges are unset
 * (WireGuard default) when both ends are zero.
 */
uint32_t
awg_range_pick(struct awg_range r)
{
	if (r.r_hi <= r.r_lo)
		return r.r_lo;
	if (r.r_lo == 0 && r.r_hi == UINT32_MAX)
		return arc4random();
	return r.r_lo + arc4random_uniform(r.r_hi - r.r_lo + 1);
}

int
awg_range_contains(struct awg_range r, uint32_t v)
{
	return r.r_lo <= v && v <= r.r_hi;
}

int
awg_range_is_zero(struct awg_range r)
{
	return r.r_lo == 0 && r.r_hi == 0;
}

int
awg_range_overlap(struct awg_range a, struct awg_range b)
{
	return a.r_lo <= b.r_hi && b.r_lo <= a.r_hi;
}

int
awg_rekey_timeout(struct awg_softc *sc)
{
	struct awg_range r = sc->sc_awg_rekey_timeout;
	return awg_range_is_zero(r) ? REKEY_TIMEOUT : awg_range_pick(r);
}

int
awg_rekey_min_timeout(struct awg_softc *sc)
{
	struct awg_range r = sc->sc_awg_rekey_timeout;
	return awg_range_is_zero(r) ? REKEY_TIMEOUT : r.r_lo;
}

int
awg_keepalive_timeout(struct awg_softc *sc)
{
	struct awg_range r = sc->sc_awg_keepalive_timeout;
	return awg_range_is_zero(r) ? KEEPALIVE_TIMEOUT : awg_range_pick(r);
}

int
awg_new_handshake_timeout(struct awg_softc *sc)
{
	struct awg_range r = sc->sc_awg_keepalive_timeout;
	return (awg_range_is_zero(r) ? KEEPALIVE_TIMEOUT : r.r_hi) +
	    awg_rekey_timeout(sc);
}

int
awg_keychain_expire_time(struct awg_softc *sc)
{
	struct awg_range r = sc->sc_awg_reject_after_time;
	return awg_range_is_zero(r) ? REJECT_AFTER_TIME : r.r_hi;
}

int
awg_max_handshake_attempts(struct awg_softc *sc)
{
	struct awg_range r = sc->sc_awg_max_handshake_attempts;
	return awg_range_is_zero(r) ? MAX_TIMER_HANDSHAKES : awg_range_pick(r);
}

void
awg_update_noise_timings(struct awg_softc *sc)
{
	struct awg_range ka = sc->sc_awg_keepalive_timeout;
	struct awg_range rt = sc->sc_awg_rekey_timeout;

	/* REKEY_AFTER_TIME_RECV = RejectAfterTime - KeepaliveTimeout -
	 * RekeyTimeout, as keyRefreshTimeoutReceiving in amneziawg-go */
	awg_noise_local_set_timings(&sc->sc_local,
	    sc->sc_awg_rekey_after_time.r_lo, sc->sc_awg_rekey_after_time.r_hi,
	    sc->sc_awg_reject_after_time.r_lo, sc->sc_awg_reject_after_time.r_hi,
	    (awg_range_is_zero(ka) ? KEEPALIVE_TIMEOUT : ka.r_lo) +
	    (awg_range_is_zero(rt) ? REKEY_TIMEOUT : rt.r_lo));
}

/*
 * Header protection: ChaCha20 (IETF, 96-bit nonce, counter 0) keyed with
 * HeaderProtectionKey, the nonce being the first 12 bytes of the random
 * S1-S4 prefix. chacha_private.h implements the 64-bit nonce variant, so
 * the first nonce word goes into the upper half of the block counter.
 */
int
awg_hp_init(struct awg_softc *sc, chacha_ctx *ctx,
    const uint8_t nonce[AWG_HPK_NONCE_LEN])
{
	uint8_t counter[8] = { 0 };

	if (!sc->sc_awg_has_hpk)
		return 0;
	chacha_keysetup(ctx, sc->sc_awg_hpk, AWG_HPK_LEN * 8);
	memcpy(counter + 4, nonce, 4);
	chacha_ivsetup(ctx, nonce + 4, counter);
	return 1;
}

/* RandomTrailers: random tail keeping the datagram within the UDP window */
size_t
awg_random_trailer(struct awg_softc *sc, uint32_t window, size_t size)
{
	if (!sc->sc_awg_random_trailers || window <= size)
		return 0;
	return arc4random_uniform(window - size);
}

size_t
awg_content_padding(struct awg_softc *sc, uint32_t window, size_t size)
{
	size_t add;

	if (window < size)
		return 0;
	add = awg_range_pick(sc->sc_awg_cpa);
	return MIN(add, window - size);
}

void
awg_peer_update_udp_window(struct awg_peer *peer, uint32_t size)
{
	/* Racy on purpose, the window only grows and is advisory */
	if (peer->p_udp_window < size)
		peer->p_udp_window = size;
}

/*
 * I1-I5: parse "<b 0xHEX><c><t><r N><rc N><rd N>" into a static packet
 * plus the regions to regenerate before each send. Text outside the tags
 * is ignored, as in amneziawg-go.
 */
static int
awg_hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int
awg_ispec_parse(struct awg_ispec *is, const char *desc)
{
	struct awg_ispec_mod	*mods = NULL;
	const char		*p, *end, *key, *val;
	uint8_t			*pkt = NULL;
	size_t			 keylen, vallen, len, i;
	size_t			 nmods = 0, pktlen = 0, mods_size = 0, pkt_size = 0;
	int			 pass, type;

	bzero(is, sizeof(*is));

	/* Pass 0 validates and computes sizes, pass 1 fills the buffers */
	for (pass = 0; pass < 2; pass++) {
		if (pass == 1) {
			if (pktlen == 0)
				return 0;
			pkt_size = pktlen;
			mods_size = nmods;
			pkt = malloc(pkt_size, M_DEVBUF, M_WAITOK | M_ZERO);
			if (mods_size > 0)
				mods = mallocarray(mods_size, sizeof(*mods),
				    M_DEVBUF, M_WAITOK | M_ZERO);
			pktlen = nmods = 0;
		}
		for (p = desc; (p = strchr(p, '<')) != NULL; p = end + 1) {
			if ((end = strchr(p, '>')) == NULL)
				return EINVAL;
			for (key = p + 1; key < end && *key == ' '; key++)
				;
			for (keylen = 0; key + keylen < end &&
			    key[keylen] != ' '; keylen++)
				;
			for (val = key + keylen; val < end && *val == ' '; val++)
				;
			for (vallen = 0; val + vallen < end &&
			    val[vallen] != ' '; vallen++)
				;

			type = 0;
			len = 0;
			if (keylen == 1 && key[0] == 'b') {
				if (vallen >= 2 && val[0] == '0' &&
				    (val[1] == 'x' || val[1] == 'X')) {
					val += 2;
					vallen -= 2;
				}
				if (vallen == 0 || vallen % 2 != 0)
					return EINVAL;
				for (i = 0; i < vallen; i++)
					if (awg_hexval(val[i]) < 0)
						return EINVAL;
				len = vallen / 2;
				if (pass == 1)
					for (i = 0; i < len; i++)
						pkt[pktlen + i] =
						    awg_hexval(val[2 * i]) << 4 |
						    awg_hexval(val[2 * i + 1]);
			} else if (keylen == 1 && key[0] == 'c') {
				type = AWG_ISPEC_MOD_COUNTER;
				len = sizeof(uint32_t);
			} else if (keylen == 1 && key[0] == 't') {
				type = AWG_ISPEC_MOD_TIME;
				len = sizeof(uint32_t);
			} else if ((keylen == 1 && key[0] == 'r') ||
			    (keylen == 2 && key[0] == 'r' &&
			    (key[1] == 'c' || key[1] == 'd'))) {
				type = keylen == 1 ? AWG_ISPEC_MOD_RAND :
				    key[1] == 'c' ? AWG_ISPEC_MOD_CHARS :
				    AWG_ISPEC_MOD_DIGITS;
				if (vallen == 0)
					return EINVAL;
				for (i = 0; i < vallen; i++) {
					if (val[i] < '0' || val[i] > '9')
						return EINVAL;
					len = len * 10 + (val[i] - '0');
					if (len > AWG_MAX_UDP_PAYLOAD)
						return EINVAL;
				}
			} else {
				return EINVAL;
			}

			if (pktlen + len > AWG_MAX_UDP_PAYLOAD)
				return EINVAL;
			if (type != 0) {
				if (pass == 1) {
					mods[nmods].im_type = type;
					mods[nmods].im_off = pktlen;
					mods[nmods].im_len = len;
				}
				nmods++;
			}
			pktlen += len;
		}
	}

	is->is_desc_size = strlen(desc) + 1;
	is->is_desc = malloc(is->is_desc_size, M_DEVBUF, M_WAITOK);
	memcpy(is->is_desc, desc, is->is_desc_size);
	is->is_pkt = pkt;
	is->is_pkt_len = pkt_size;
	is->is_mods = mods;
	is->is_mods_count = mods_size;
	return 0;
}

void
awg_ispec_free(struct awg_ispec *is)
{
	if (is->is_desc != NULL)
		free(is->is_desc, M_DEVBUF, is->is_desc_size);
	if (is->is_pkt != NULL)
		free(is->is_pkt, M_DEVBUF, is->is_pkt_len);
	if (is->is_mods != NULL)
		free(is->is_mods, M_DEVBUF,
		    is->is_mods_count * sizeof(*is->is_mods));
	bzero(is, sizeof(*is));
}

/*
 * The following section handles the timeout callbacks for a WireGuard session.
 * These functions provide an "event based" model for controlling awg(4) session
 * timers. All function calls occur after the specified event below.
 *
 * awg_timers_event_data_sent:
 *	tx: data
 * awg_timers_event_data_received:
 *	rx: data
 * awg_timers_event_any_authenticated_packet_sent:
 *	tx: keepalive, data, handshake
 * awg_timers_event_any_authenticated_packet_received:
 *	rx: keepalive, data, handshake
 * awg_timers_event_any_authenticated_packet_traversal:
 *	tx, rx: keepalive, data, handshake
 * awg_timers_event_handshake_initiated:
 *	tx: initiation
 * awg_timers_event_handshake_responded:
 *	tx: response
 * awg_timers_event_handshake_complete:
 *	rx: response, confirmation data
 * awg_timers_event_session_derived:
 *	tx: response, rx: response
 * awg_timers_event_want_initiation:
 *	tx: data failed, old keys expiring
 * awg_timers_event_reset_handshake_last_sent:
 * 	anytime we may immediately want a new handshake
 */
void
awg_timers_init(struct awg_timers *t)
{
	bzero(t, sizeof(*t));
	mtx_init_flags(&t->t_mtx, IPL_NET, "awg_timers", 0);
	mtx_init(&t->t_handshake_mtx, IPL_NET);
	t->t_max_handshake_retries = MAX_TIMER_HANDSHAKES;

	timeout_set(&t->t_new_handshake, awg_timers_run_new_handshake, t);
	timeout_set(&t->t_send_keepalive, awg_timers_run_send_keepalive, t);
	timeout_set(&t->t_retry_handshake, awg_timers_run_retry_handshake, t);
	timeout_set(&t->t_persistent_keepalive,
	    awg_timers_run_persistent_keepalive, t);
	timeout_set(&t->t_zero_key_material,
	    awg_timers_run_zero_key_material, t);
}

void
awg_timers_enable(struct awg_timers *t)
{
	mtx_enter(&t->t_mtx);
	t->t_disabled = 0;
	mtx_leave(&t->t_mtx);
	awg_timers_run_persistent_keepalive(t);
}

void
awg_timers_disable(struct awg_timers *t)
{
	mtx_enter(&t->t_mtx);
	t->t_disabled = 1;
	t->t_need_another_keepalive = 0;
	mtx_leave(&t->t_mtx);

	timeout_del_barrier(&t->t_new_handshake);
	timeout_del_barrier(&t->t_send_keepalive);
	timeout_del_barrier(&t->t_retry_handshake);
	timeout_del_barrier(&t->t_persistent_keepalive);
	timeout_del_barrier(&t->t_zero_key_material);
}

void
awg_timers_set_persistent_keepalive(struct awg_timers *t, uint16_t interval,
    uint16_t interval_hi)
{
	mtx_enter(&t->t_mtx);
	if (!t->t_disabled) {
		t->t_persistent_keepalive_interval = interval;
		t->t_persistent_keepalive_hi = MAX(interval, interval_hi);
		awg_timers_run_persistent_keepalive(t);
	}
	mtx_leave(&t->t_mtx);
}

int
awg_timers_get_persistent_keepalive(struct awg_timers *t, uint16_t *interval,
    uint16_t *interval_hi)
{
	*interval = t->t_persistent_keepalive_interval;
	*interval_hi = t->t_persistent_keepalive_hi;
	return *interval > 0 ? 0 : ENOENT;
}

void
awg_timers_get_last_handshake(struct awg_timers *t, struct timespec *time)
{
	mtx_enter(&t->t_handshake_mtx);
	*time = t->t_handshake_complete;
	mtx_leave(&t->t_handshake_mtx);
}

int
awg_timers_expired_handshake_last_sent(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	struct timespec uptime;
	struct timespec expire = {
		.tv_sec = awg_rekey_min_timeout(peer->p_sc), .tv_nsec = 0 };

	getnanouptime(&uptime);
	timespecadd(&t->t_handshake_last_sent, &expire, &expire);
	return timespeccmp(&uptime, &expire, >) ? ETIMEDOUT : 0;
}

int
awg_timers_check_handshake_last_sent(struct awg_timers *t)
{
	int ret;
	mtx_enter(&t->t_handshake_mtx);
	if ((ret = awg_timers_expired_handshake_last_sent(t)) == ETIMEDOUT)
		getnanouptime(&t->t_handshake_last_sent);
	mtx_leave(&t->t_handshake_mtx);
	return ret;
}

void
awg_timers_event_data_sent(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	int	msecs = awg_new_handshake_timeout(peer->p_sc) * 1000;
	msecs += arc4random_uniform(REKEY_TIMEOUT_JITTER);

	mtx_enter(&t->t_mtx);
	if (!t->t_disabled && !timeout_pending(&t->t_new_handshake))
		timeout_add_msec(&t->t_new_handshake, msecs);
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_data_received(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);

	mtx_enter(&t->t_mtx);
	if (!t->t_disabled) {
		if (!timeout_pending(&t->t_send_keepalive))
			timeout_add_sec(&t->t_send_keepalive,
			    awg_keepalive_timeout(peer->p_sc));
		else
			t->t_need_another_keepalive = 1;
	}
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_any_authenticated_packet_sent(struct awg_timers *t)
{
	timeout_del(&t->t_send_keepalive);
}

void
awg_timers_event_any_authenticated_packet_received(struct awg_timers *t)
{
	timeout_del(&t->t_new_handshake);
}

void
awg_timers_event_any_authenticated_packet_traversal(struct awg_timers *t)
{
	struct awg_range pka;

	mtx_enter(&t->t_mtx);
	if (!t->t_disabled && t->t_persistent_keepalive_interval > 0) {
		pka.r_lo = t->t_persistent_keepalive_interval;
		pka.r_hi = t->t_persistent_keepalive_hi;
		timeout_add_sec(&t->t_persistent_keepalive,
		    awg_range_pick(pka));
	}
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_handshake_initiated(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	int	msecs = awg_rekey_timeout(peer->p_sc) * 1000;
	msecs += arc4random_uniform(REKEY_TIMEOUT_JITTER);

	mtx_enter(&t->t_mtx);
	if (!t->t_disabled)
		timeout_add_msec(&t->t_retry_handshake, msecs);
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_handshake_responded(struct awg_timers *t)
{
	mtx_enter(&t->t_handshake_mtx);
	getnanouptime(&t->t_handshake_last_sent);
	mtx_leave(&t->t_handshake_mtx);
}

void
awg_timers_event_handshake_complete(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);

	mtx_enter(&t->t_mtx);
	if (!t->t_disabled) {
		mtx_enter(&t->t_handshake_mtx);
		timeout_del(&t->t_retry_handshake);
		t->t_handshake_retries = 0;
		t->t_max_handshake_retries =
		    awg_max_handshake_attempts(peer->p_sc);
		getnanotime(&t->t_handshake_complete);
		mtx_leave(&t->t_handshake_mtx);
		awg_timers_run_send_keepalive(t);
	}
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_session_derived(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);

	mtx_enter(&t->t_mtx);
	if (!t->t_disabled)
		timeout_add_sec(&t->t_zero_key_material,
		    awg_keychain_expire_time(peer->p_sc) * 3);
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_want_initiation(struct awg_timers *t)
{
	mtx_enter(&t->t_mtx);
	if (!t->t_disabled)
		awg_timers_run_send_initiation(t, 0);
	mtx_leave(&t->t_mtx);
}

void
awg_timers_event_reset_handshake_last_sent(struct awg_timers *t)
{
	struct awg_peer	*peer = CONTAINER_OF(t, struct awg_peer, p_timers);

	mtx_enter(&t->t_handshake_mtx);
	t->t_handshake_last_sent.tv_sec -=
	    (awg_rekey_min_timeout(peer->p_sc) + 1);
	mtx_leave(&t->t_handshake_mtx);
}

void
awg_timers_run_send_initiation(void *_t, int is_retry)
{
	struct awg_timers *t = _t;
	struct awg_peer	 *peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	if (!is_retry) {
		t->t_handshake_retries = 0;
		t->t_max_handshake_retries =
		    awg_max_handshake_attempts(peer->p_sc);
	}
	if (awg_timers_expired_handshake_last_sent(t) == ETIMEDOUT)
		task_add(awg_handshake_taskq, &peer->p_send_initiation);
}

void
awg_timers_run_retry_handshake(void *_t)
{
	struct awg_timers *t = _t;
	struct awg_peer	 *peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	char		  ipaddr[INET6_ADDRSTRLEN];

	mtx_enter(&t->t_handshake_mtx);
	if (t->t_handshake_retries <= t->t_max_handshake_retries) {
		t->t_handshake_retries++;
		mtx_leave(&t->t_handshake_mtx);

		AWGPRINTF(LOG_INFO, peer->p_sc, &peer->p_endpoint_mtx,
		    "Handshake for peer %llu (%s) did not complete after %d "
		    "seconds, retrying (try %d)\n", peer->p_id,
		    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
		        sizeof(ipaddr)),
		    awg_rekey_min_timeout(peer->p_sc),
		    t->t_handshake_retries + 1);
		awg_peer_clear_src(peer);
		awg_timers_run_send_initiation(t, 1);
	} else {
		mtx_leave(&t->t_handshake_mtx);

		AWGPRINTF(LOG_INFO, peer->p_sc, &peer->p_endpoint_mtx,
		    "Handshake for peer %llu (%s) did not complete after %d "
		    "retries, giving up\n", peer->p_id,
		    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
		        sizeof(ipaddr)), t->t_max_handshake_retries + 2);

		timeout_del(&t->t_send_keepalive);
		mq_purge(&peer->p_stage_queue);
		if (!timeout_pending(&t->t_zero_key_material))
			timeout_add_sec(&t->t_zero_key_material,
			    awg_keychain_expire_time(peer->p_sc) * 3);
	}
}

void
awg_timers_run_send_keepalive(void *_t)
{
	struct awg_timers *t = _t;
	struct awg_peer	 *peer = CONTAINER_OF(t, struct awg_peer, p_timers);

	task_add(awg_crypt_taskq, &peer->p_send_keepalive);
	if (t->t_need_another_keepalive) {
		t->t_need_another_keepalive = 0;
		timeout_add_sec(&t->t_send_keepalive,
		    awg_keepalive_timeout(peer->p_sc));
	}
}

void
awg_timers_run_new_handshake(void *_t)
{
	struct awg_timers *t = _t;
	struct awg_peer	 *peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	char		  ipaddr[INET6_ADDRSTRLEN];

	AWGPRINTF(LOG_INFO, peer->p_sc, &peer->p_endpoint_mtx,
	    "Retrying handshake with peer %llu (%s) because we "
	    "stopped hearing back after %d seconds\n", peer->p_id,
	    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
	        sizeof(ipaddr)), awg_new_handshake_timeout(peer->p_sc));
	awg_peer_clear_src(peer);

	awg_timers_run_send_initiation(t, 0);
}

void
awg_timers_run_zero_key_material(void *_t)
{
	struct awg_timers *t = _t;
	struct awg_peer	 *peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	char		  ipaddr[INET6_ADDRSTRLEN];

	AWGPRINTF(LOG_INFO, peer->p_sc, &peer->p_endpoint_mtx, "Zeroing out "
	    "keys for peer %llu (%s)\n", peer->p_id,
	    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
	        sizeof(ipaddr)));
	task_add(awg_handshake_taskq, &peer->p_clear_secrets);
}

void
awg_timers_run_persistent_keepalive(void *_t)
{
	struct awg_timers *t = _t;
	struct awg_peer	 *peer = CONTAINER_OF(t, struct awg_peer, p_timers);
	if (t->t_persistent_keepalive_interval != 0)
		task_add(awg_crypt_taskq, &peer->p_send_keepalive);
}

/* The following functions handle handshakes */
void
awg_peer_send_buf(struct awg_peer *peer, uint8_t *buf, size_t len)
{
	struct awg_endpoint	 endpoint;

	awg_peer_counters_add(peer, len, 0);
	awg_timers_event_any_authenticated_packet_traversal(&peer->p_timers);
	awg_timers_event_any_authenticated_packet_sent(&peer->p_timers);
	awg_peer_get_endpoint(peer, &endpoint);
	awg_send_buf(peer->p_sc, &endpoint, buf, len);
}

/*
 * Send a handshake message: S1-S3 random prefix, the message (encrypted with
 * the header protection key, if any) and an optional random trailer.
 * peer == NULL (cookie replies) uses the default UDP window.
 */
void
awg_send_hs(struct awg_softc *sc, struct awg_peer *peer,
    struct awg_endpoint *e, void *msg, size_t len, uint16_t padding)
{
	chacha_ctx	 ctx;
	uint8_t		*buf;
	size_t		 trailer, total;

	trailer = awg_random_trailer(sc, peer != NULL ?
	    peer->p_udp_window : AWG_DEFAULT_UDP_WINDOW, padding + len);
	total = padding + len + trailer;
	if ((buf = malloc(total, M_TEMP, M_NOWAIT)) == NULL)
		return;

	arc4random_buf(buf, padding);
	memcpy(buf + padding, msg, len);
	arc4random_buf(buf + padding + len, trailer);

	if (padding >= AWG_HPK_NONCE_LEN && awg_hp_init(sc, &ctx, buf)) {
		chacha_encrypt_bytes(&ctx, buf + padding, buf + padding, len);
		explicit_bzero(&ctx, sizeof(ctx));
	}

	if (peer != NULL)
		awg_peer_send_buf(peer, buf, total);
	else
		awg_send_buf(sc, e, buf, total);
	free(buf, M_TEMP, total);
}

void
awg_send_junk(struct awg_softc *sc, struct awg_peer *peer)
{
	struct awg_endpoint	endpoint;
	uint8_t			buf[1500];
	uint16_t		pktlen;
	int			i;

	if (sc->sc_awg_jc == 0 || sc->sc_awg_jmin == 0 ||
	    sc->sc_awg_jmax < sc->sc_awg_jmin ||
	    sc->sc_awg_jmax > sizeof(buf))
		return;

	awg_peer_get_endpoint(peer, &endpoint);
	for (i = 0; i < sc->sc_awg_jc; i++) {
		if (sc->sc_awg_jmin == sc->sc_awg_jmax)
			pktlen = sc->sc_awg_jmin;
		else
			pktlen = sc->sc_awg_jmin + (uint16_t)
			    arc4random_uniform(sc->sc_awg_jmax - sc->sc_awg_jmin + 1);
		arc4random_buf(buf, pktlen);
		awg_send_buf(sc, &endpoint, buf, pktlen);
	}
}

/* I1-I5 signature packets, sent in order before the junk packets */
void
awg_send_ispecs(struct awg_softc *sc, struct awg_peer *peer)
{
	struct awg_endpoint	 endpoint;
	struct awg_ispec	*is;
	struct awg_ispec_mod	*mod;
	struct timespec		 now;
	uint32_t		 counter, val;
	uint8_t			*buf, *p;
	size_t			 i, j, len;

	if (sc->sc_awg_version != AWG_VERSION_3_1)
		return;

	awg_peer_get_endpoint(peer, &endpoint);
	counter = arc4random();

	rw_enter_read(&sc->sc_ispec_lock);
	for (i = 0; i < AWG_ISPEC_COUNT; i++) {
		is = &sc->sc_awg_ispec[i];
		if (is->is_pkt_len == 0)
			continue;
		if ((buf = malloc(is->is_pkt_len, M_TEMP, M_NOWAIT)) == NULL)
			break;
		memcpy(buf, is->is_pkt, is->is_pkt_len);
		for (j = 0; j < is->is_mods_count; j++) {
			mod = &is->is_mods[j];
			p = buf + mod->im_off;
			switch (mod->im_type) {
			case AWG_ISPEC_MOD_COUNTER:
				val = htobe32(counter);
				memcpy(p, &val, sizeof(val));
				break;
			case AWG_ISPEC_MOD_TIME:
				getnanotime(&now);
				val = htobe32((uint32_t)now.tv_sec);
				memcpy(p, &val, sizeof(val));
				break;
			case AWG_ISPEC_MOD_RAND:
				arc4random_buf(p, mod->im_len);
				break;
			case AWG_ISPEC_MOD_CHARS:
				for (len = 0; len < mod->im_len; len++) {
					val = arc4random_uniform(52);
					p[len] = val < 26 ? 'a' + val :
					    'A' + val - 26;
				}
				break;
			case AWG_ISPEC_MOD_DIGITS:
				for (len = 0; len < mod->im_len; len++)
					p[len] = '0' + arc4random_uniform(10);
				break;
			}
		}
		awg_send_buf(sc, &endpoint, buf, is->is_pkt_len);
		free(buf, M_TEMP, is->is_pkt_len);
		counter++;
	}
	rw_exit_read(&sc->sc_ispec_lock);
}

void
awg_send_initiation(void *_peer)
{
	struct awg_peer			*peer = _peer;
	struct awg_softc		*sc = peer->p_sc;
	struct awg_pkt_initiation	 pkt;
	char				 ipaddr[INET6_ADDRSTRLEN];

	if (awg_timers_check_handshake_last_sent(&peer->p_timers) != ETIMEDOUT)
		return;

	AWGPRINTF(LOG_INFO, sc, &peer->p_endpoint_mtx, "Sending "
	    "handshake initiation to peer %llu (%s)\n", peer->p_id,
	    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
	        sizeof(ipaddr)));

	if (awg_noise_create_initiation(&peer->p_remote, &pkt.s_idx, pkt.ue, pkt.es,
				    pkt.ets) != 0)
		return;
	pkt.t = htole32(awg_range_pick(sc->sc_awg_h1));
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt)-sizeof(pkt.m));

	awg_send_ispecs(sc, peer);

	if (sc->sc_awg_jc > 0)
		awg_send_junk(sc, peer);

	awg_send_hs(sc, peer, NULL, &pkt, sizeof(pkt), sc->sc_awg_s1);
	awg_timers_event_handshake_initiated(&peer->p_timers);
}

void
awg_send_response(struct awg_peer *peer)
{
	struct awg_softc		*sc = peer->p_sc;
	struct awg_pkt_response	 pkt;
	char			 ipaddr[INET6_ADDRSTRLEN];

	AWGPRINTF(LOG_INFO, peer->p_sc, &peer->p_endpoint_mtx, "Sending "
	    "handshake response to peer %llu (%s)\n", peer->p_id,
	    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
	        sizeof(ipaddr)));

	if (awg_noise_create_response(&peer->p_remote, &pkt.s_idx, &pkt.r_idx,
				  pkt.ue, pkt.en) != 0)
		return;
	if (awg_noise_remote_begin_session(&peer->p_remote) != 0)
		return;
	awg_timers_event_session_derived(&peer->p_timers);
	pkt.t = htole32(awg_range_pick(sc->sc_awg_h2));
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt)-sizeof(pkt.m));
	awg_timers_event_handshake_responded(&peer->p_timers);
	awg_send_hs(sc, peer, NULL, &pkt, sizeof(pkt), sc->sc_awg_s2);
}

void
awg_send_cookie(struct awg_softc *sc, struct cookie_macs *cm, uint32_t idx,
    struct awg_endpoint *e)
{
	struct awg_pkt_cookie	pkt;

	AWGPRINTF(LOG_DEBUG, sc, NULL, "Sending cookie response for denied "
	    "handshake message\n");

	pkt.t = htole32(awg_range_pick(sc->sc_awg_h3));
	pkt.r_idx = idx;

	cookie_checker_create_payload(&sc->sc_cookie, cm, pkt.nonce,
	    pkt.ec, &e->e_remote.r_sa);

	awg_send_hs(sc, NULL, e, &pkt, sizeof(pkt), sc->sc_awg_s3);
}

void
awg_send_keepalive(void *_peer)
{
	struct awg_peer	*peer = _peer;
	struct awg_softc	*sc = peer->p_sc;
	struct awg_tag	*t;
	struct mbuf	*m;

	if (!mq_empty(&peer->p_stage_queue))
		goto send;

	if ((m = m_gethdr(M_NOWAIT, MT_DATA)) == NULL)
		return;

	if ((t = awg_tag_get(m)) == NULL) {
		m_freem(m);
		return;
	}

	t->t_peer = peer;
	t->t_mbuf = NULL;
	t->t_done = 0;
	t->t_mtu = 0; /* MTU == 0 OK for keepalive */

	mq_push(&peer->p_stage_queue, m);
send:
	if (awg_noise_remote_ready(&peer->p_remote) == 0) {
		awg_queue_out(sc, peer);
		task_add(awg_crypt_taskq, &sc->sc_encap);
	} else {
		awg_timers_event_want_initiation(&peer->p_timers);
	}
}

void
awg_peer_clear_secrets(void *_peer)
{
	struct awg_peer *peer = _peer;
	awg_noise_remote_clear(&peer->p_remote);
}

void
awg_handshake(struct awg_softc *sc, struct mbuf *m)
{
	struct awg_tag			*t;
	struct awg_pkt_initiation	*init;
	struct awg_pkt_response		*resp;
	struct awg_pkt_cookie		*cook;
	struct awg_peer			*peer;
	struct awg_noise_remote		*remote;
	int				 res, underload = 0;
	static struct timeval		 awg_last_underload; /* microuptime */
	char				 ipaddr[INET6_ADDRSTRLEN];

	if (sc->sc_awg_disable_cookies) {
		/* DisableCookies: never ask for a cookie, never ratelimit */
		underload = 0;
	} else if (mq_len(&sc->sc_handshake_queue) >= MAX_QUEUED_HANDSHAKES/8) {
		getmicrouptime(&awg_last_underload);
		underload = 1;
	} else if (awg_last_underload.tv_sec != 0) {
		if (!ratecheck(&awg_last_underload, &awg_underload_interval))
			underload = 1;
		else
			bzero(&awg_last_underload, sizeof(awg_last_underload));
	}

	t = awg_tag_get(m);

	switch (t->t_type) {
	case AWG_TYPE_INITIATION:
		init = mtod(m, struct awg_pkt_initiation *);

		res = cookie_checker_validate_macs(&sc->sc_cookie, &init->m,
				init, sizeof(*init) - sizeof(init->m),
				underload, &t->t_endpoint.e_remote.r_sa);

		if (res == EINVAL) {
			AWGPRINTF(LOG_INFO, sc, NULL, "Invalid initiation "
			    "MAC from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		} else if (res == ECONNREFUSED) {
			AWGPRINTF(LOG_DEBUG, sc, NULL, "Handshake "
			    "ratelimited from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		} else if (res == EAGAIN) {
			awg_send_cookie(sc, &init->m, init->s_idx,
			    &t->t_endpoint);
			goto error;
		} else if (res != 0) {
			panic("unexpected response: %d", res);
		}

		if (awg_noise_consume_initiation(&sc->sc_local, &remote,
		    init->s_idx, init->ue, init->es, init->ets) != 0) {
			AWGPRINTF(LOG_INFO, sc, NULL, "Invalid handshake "
			    "initiation from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		}

		peer = CONTAINER_OF(remote, struct awg_peer, p_remote);

		AWGPRINTF(LOG_INFO, sc, NULL, "Receiving handshake initiation "
		    "from peer %llu (%s)\n", peer->p_id,
		    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
		        sizeof(ipaddr)));

		awg_peer_counters_add(peer, 0, sizeof(*init));
		awg_peer_set_endpoint_from_tag(peer, t);
		awg_send_response(peer);
		break;
	case AWG_TYPE_RESPONSE:
		resp = mtod(m, struct awg_pkt_response *);

		res = cookie_checker_validate_macs(&sc->sc_cookie, &resp->m,
				resp, sizeof(*resp) - sizeof(resp->m),
				underload, &t->t_endpoint.e_remote.r_sa);

		if (res == EINVAL) {
			AWGPRINTF(LOG_INFO, sc, NULL, "Invalid response "
			    "MAC from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		} else if (res == ECONNREFUSED) {
			AWGPRINTF(LOG_DEBUG, sc, NULL, "Handshake "
			    "ratelimited from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		} else if (res == EAGAIN) {
			awg_send_cookie(sc, &resp->m, resp->s_idx,
			    &t->t_endpoint);
			goto error;
		} else if (res != 0) {
			panic("unexpected response: %d", res);
		}

		if ((remote = awg_index_get(sc, resp->r_idx)) == NULL) {
			AWGPRINTF(LOG_INFO, sc, NULL, "Unknown "
			    "handshake response from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		}

		peer = CONTAINER_OF(remote, struct awg_peer, p_remote);

		if (awg_noise_consume_response(remote, resp->s_idx, resp->r_idx,
					   resp->ue, resp->en) != 0) {
			AWGPRINTF(LOG_INFO, sc, NULL, "Invalid handshake "
			    "response from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		}

		AWGPRINTF(LOG_INFO, sc, NULL, "Receiving handshake response "
		    "from peer %llu (%s)\n", peer->p_id,
		    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
		        sizeof(ipaddr)));

		awg_peer_counters_add(peer, 0, sizeof(*resp));
		awg_peer_set_endpoint_from_tag(peer, t);
		if (awg_noise_remote_begin_session(&peer->p_remote) == 0) {
			awg_timers_event_session_derived(&peer->p_timers);
			awg_timers_event_handshake_complete(&peer->p_timers);
		}
		break;
	case AWG_TYPE_COOKIE:
		cook = mtod(m, struct awg_pkt_cookie *);

		if ((remote = awg_index_get(sc, cook->r_idx)) == NULL) {
			AWGPRINTF(LOG_DEBUG, sc, NULL, "Unknown cookie "
			    "index from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		}

		peer = CONTAINER_OF(remote, struct awg_peer, p_remote);

		if (cookie_maker_consume_payload(&peer->p_cookie,
		    cook->nonce, cook->ec) != 0) {
			AWGPRINTF(LOG_DEBUG, sc, NULL, "Could not decrypt "
			    "cookie response from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
			        sizeof(ipaddr)));
			goto error;
		}

		AWGPRINTF(LOG_DEBUG, sc, NULL, "Receiving cookie response "
		    "from %s\n",
		    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa, ipaddr,
		        sizeof(ipaddr)));
		goto error;
	default:
		panic("invalid packet in handshake queue");
	}

	awg_timers_event_any_authenticated_packet_received(&peer->p_timers);
	awg_timers_event_any_authenticated_packet_traversal(&peer->p_timers);
error:
	m_freem(m);
}

void
awg_handshake_worker(void *_sc)
{
	struct mbuf *m;
	struct awg_softc *sc = _sc;
	while ((m = mq_dequeue(&sc->sc_handshake_queue)) != NULL)
		awg_handshake(sc, m);
}

/*
 * The following functions handle encapsulation (encryption) and
 * decapsulation (decryption). The awg_{en,de}cap functions will run in the
 * sc_crypt_taskq, while awg_deliver_{in,out} must be serialised and will run
 * in nettq.
 *
 * The packets are tracked in two queues, a serial queue and a parallel queue.
 *  - The parallel queue is used to distribute the encryption across multiple
 *    threads.
 *  - The serial queue ensures that packets are not reordered and are
 *    delivered in sequence.
 * The awg_tag attached to the packet contains two flags to help the two queues
 * interact.
 *  - t_done: The parallel queue has finished with the packet, now the serial
 *            queue can do it's work.
 *  - t_mbuf: Used to store the *crypted packet. in the case of encryption,
 *            this is a newly allocated packet, and in the case of decryption,
 *            it is a pointer to the same packet, that has been decrypted and
 *            truncated. If t_mbuf is NULL, then *cryption failed and this
 *            packet should not be passed.
 * wg_{en,de}cap work on the parallel queue, while awg_deliver_{in,out} work
 * on the serial queue.
 */
void
awg_encap(struct awg_softc *sc, struct mbuf *m)
{
	int res = 0;
	struct awg_pkt_data	*data;
	struct awg_peer		*peer;
	struct awg_tag		*t;
	struct mbuf		*mc;
	chacha_ctx		 ctx;
	uint8_t			*prefix;
	size_t			 padding_len, plaintext_len, out_len, size;
	uint64_t		 nonce;
	uint16_t		 s4 = sc->sc_awg_s4;
	char			 ipaddr[INET6_ADDRSTRLEN];

	t = awg_tag_get(m);
	peer = t->t_peer;

	/*
	 * Transport padding inside the encrypted payload: ContentPaddingAddition
	 * or RandomTrailers (3.1, bounded by the peer's UDP window), otherwise
	 * the WireGuard multiple of 16.
	 */
	size = s4 + AWG_MIN_DATA_SIZE + m->m_pkthdr.len;
	awg_peer_update_udp_window(peer, size);
	if (!awg_range_is_zero(sc->sc_awg_cpa))
		padding_len = awg_content_padding(sc, peer->p_udp_window, size);
	else if (sc->sc_awg_random_trailers)
		padding_len = awg_random_trailer(sc, peer->p_udp_window, size);
	else
		padding_len = AWG_PKT_WITH_PADDING(m->m_pkthdr.len) -
		    m->m_pkthdr.len;
	plaintext_len = m->m_pkthdr.len + padding_len;
	out_len = s4 + sizeof(struct awg_pkt_data) + plaintext_len +
	    NOISE_AUTHTAG_LEN;

	/*
	 * For the time being we allocate a new packet with sufficient size to
	 * hold the encrypted data and headers. It would be difficult to
	 * overcome as p_encap_queue (mbuf_list) holds a reference to the mbuf.
	 * If we m_makespace or similar, we risk corrupting that list.
	 * Additionally, we only pass a buf and buf length to
	 * awg_noise_remote_encrypt. Technically it would be possible to teach
	 * awg_noise_remote_encrypt about mbufs, but we would need to sort out the
	 * p_encap_queue situation first.
	 */
	if ((mc = m_clget(NULL, M_NOWAIT, out_len + max_hdr)) == NULL)
		goto error;
	m_align(mc, out_len);

	/* S4 random prefix, then the transport message */
	prefix = mtod(mc, uint8_t *);
	arc4random_buf(prefix, s4);
	data = (struct awg_pkt_data *)(prefix + s4);
	m_copydata(m, 0, m->m_pkthdr.len, data->buf);
	bzero(data->buf + m->m_pkthdr.len, padding_len);
	data->t = htole32(awg_range_pick(sc->sc_awg_h4));

	/*
	 * Copy the flow hash from the inner packet to the outer packet, so
	 * that fq_codel can properly separate streams, rather than falling
	 * back to random buckets.
	 */
	mc->m_pkthdr.ph_flowid = m->m_pkthdr.ph_flowid;

	mc->m_pkthdr.pf.prio = m->m_pkthdr.pf.prio;

	res = awg_noise_remote_encrypt(&peer->p_remote, &data->r_idx, &nonce,
				   data->buf, plaintext_len);
	nonce = htole64(nonce); /* Wire format is little endian. */
	memcpy(data->nonce, &nonce, sizeof(data->nonce));

	if (s4 >= AWG_HPK_NONCE_LEN && awg_hp_init(sc, &ctx, prefix)) {
		chacha_encrypt_bytes(&ctx, (uint8_t *)data, (uint8_t *)data,
		    sizeof(*data));
		explicit_bzero(&ctx, sizeof(ctx));
	}

	if (__predict_false(res == EINVAL)) {
		m_freem(mc);
		goto error;
	} else if (__predict_false(res == ESTALE)) {
		awg_timers_event_want_initiation(&peer->p_timers);
	} else if (__predict_false(res != 0)) {
		panic("unexpected result: %d", res);
	}

	/* A packet with length 0 is a keepalive packet */
	if (__predict_false(m->m_pkthdr.len == 0))
		AWGPRINTF(LOG_DEBUG, sc, &peer->p_endpoint_mtx, "Sending "
		    "keepalive packet to peer %llu (%s)\n", peer->p_id,
		    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa, ipaddr,
		        sizeof(ipaddr)));

	mc->m_pkthdr.ph_loopcnt = m->m_pkthdr.ph_loopcnt;
	mc->m_flags &= ~(M_MCAST | M_BCAST);
	mc->m_pkthdr.len = mc->m_len = out_len;

	/*
	 * We would count ifc_opackets, ifc_obytes of m here, except if_snd
	 * already does that for us, so no need to worry about it.
	counters_pkt(sc->sc_if.if_counters, ifc_opackets, ifc_obytes,
	    m->m_pkthdr.len);
	 */
	awg_peer_counters_add(peer, mc->m_pkthdr.len, 0);

	t->t_mbuf = mc;
error:
	t->t_done = 1;
	task_add(net_tq(sc->sc_if.if_index), &peer->p_deliver_out);
}

void
awg_decap(struct awg_softc *sc, struct mbuf *m)
{
	int			 res, len;
	struct ip		*ip;
	struct ip6_hdr		*ip6;
	struct awg_pkt_data	*data;
	struct awg_peer		*peer, *allowed_peer;
	struct awg_tag		*t;
	size_t			 payload_len;
	uint64_t		 nonce;
	char			 ipaddr[INET6_ADDRSTRLEN];

	t = awg_tag_get(m);
	peer = t->t_peer;

	/*
	 * Likewise to awg_encap, we pass a buf and buf length to 
	 * awg_noise_remote_decrypt. Again, possible to teach it about mbufs
	 * but need to get over the p_decap_queue situation first. However,
	 * we do not need to allocate a new mbuf as the decrypted packet is
	 * strictly smaller than encrypted. We just set t_mbuf to m and
	 * awg_deliver_in knows how to deal with that.
	 */
	data = mtod(m, struct awg_pkt_data *);
	payload_len = m->m_pkthdr.len - sizeof(struct awg_pkt_data);
	memcpy(&nonce, data->nonce, sizeof(nonce));
	nonce = le64toh(nonce); /* Wire format is little endian. */
	res = awg_noise_remote_decrypt(&peer->p_remote, data->r_idx, nonce,
				   data->buf, payload_len);

	if (__predict_false(res == EINVAL)) {
		goto error;
	} else if (__predict_false(res == ECONNRESET)) {
		awg_timers_event_handshake_complete(&peer->p_timers);
	} else if (__predict_false(res == ESTALE)) {
		awg_timers_event_want_initiation(&peer->p_timers);
	} else if (__predict_false(res != 0)) {
		panic("unexpected response: %d", res);
	}

	awg_peer_set_endpoint_from_tag(peer, t);

	awg_peer_counters_add(peer, 0, m->m_pkthdr.len);

	m_adj(m, sizeof(struct awg_pkt_data));
	m_adj(m, -NOISE_AUTHTAG_LEN);

	awg_peer_update_udp_window(peer,
	    sc->sc_awg_s4 + AWG_MIN_DATA_SIZE + m->m_pkthdr.len);

	/*
	 * With S4, ContentPaddingAddition or RandomTrailers a keepalive
	 * carries zero padding: no IP version nibble means keepalive.
	 */
	if (m->m_pkthdr.len > 0 && *mtod(m, uint8_t *) == 0)
		m_adj(m, -m->m_pkthdr.len);

	counters_pkt(sc->sc_if.if_counters, ifc_ipackets, ifc_ibytes,
	    m->m_pkthdr.len);

	/* A packet with length 0 is a keepalive packet */
	if (__predict_false(m->m_pkthdr.len == 0)) {
		AWGPRINTF(LOG_DEBUG, sc, &peer->p_endpoint_mtx, "Receiving "
		    "keepalive packet from peer %llu (%s)\n", peer->p_id,
		    sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa,
		        ipaddr, sizeof(ipaddr)));
		goto done;
	}

	/*
	 * We can let the network stack handle the intricate validation of the
	 * IP header, we just worry about the sizeof and the version, so we can
	 * read the source address in awg_aip_lookup.
	 *
	 * We also need to trim the packet, as it was likely padded before
	 * encryption. While we could drop it here, it will be more helpful to
	 * pass it to bpf_mtap and use the counters that people are expecting
	 * in ipv4_input and ipv6_input. We can rely on ipv4_input and
	 * ipv6_input to properly validate the headers.
	 */
	ip = mtod(m, struct ip *);
	ip6 = mtod(m, struct ip6_hdr *);

	if (m->m_pkthdr.len >= sizeof(struct ip) && ip->ip_v == IPVERSION) {
		m->m_pkthdr.ph_family = AF_INET;

		len = ntohs(ip->ip_len);
		if (len >= sizeof(struct ip) && len < m->m_pkthdr.len)
			m_adj(m, len - m->m_pkthdr.len);

		allowed_peer = awg_aip_lookup(sc->sc_aip4, &ip->ip_src);
#ifdef INET6
	} else if (m->m_pkthdr.len >= sizeof(struct ip6_hdr) &&
	    (ip6->ip6_vfc & IPV6_VERSION_MASK) == IPV6_VERSION) {
		m->m_pkthdr.ph_family = AF_INET6;

		len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
		if (len < m->m_pkthdr.len)
			m_adj(m, len - m->m_pkthdr.len);

		allowed_peer = awg_aip_lookup(sc->sc_aip6, &ip6->ip6_src);
#endif
	} else {
		AWGPRINTF(LOG_WARNING, sc, &peer->p_endpoint_mtx, "Packet "
		    "is neither IPv4 nor IPv6 from peer %llu (%s)\n",
		    peer->p_id, sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa,
		        ipaddr, sizeof(ipaddr)));
		goto error;
	}

	if (__predict_false(peer != allowed_peer)) {
		AWGPRINTF(LOG_WARNING, sc, &peer->p_endpoint_mtx, "Packet "
                    "has unallowed source IP from peer %llu (%s)\n",
                    peer->p_id, sockaddr_ntop(&peer->p_endpoint.e_remote.r_sa,
                        ipaddr, sizeof(ipaddr)));
		goto error;
	}

	/* tunneled packet was not offloaded */
	m->m_pkthdr.csum_flags = 0;

	m->m_pkthdr.ph_ifidx = sc->sc_if.if_index;
	m->m_pkthdr.ph_rtableid = sc->sc_if.if_rdomain;
	m->m_flags &= ~(M_MCAST | M_BCAST);
#if NPF > 0
	pf_pkt_addr_changed(m);
#endif /* NPF > 0 */

done:
	t->t_mbuf = m;
error:
	t->t_done = 1;
	task_add(net_tq(sc->sc_if.if_index), &peer->p_deliver_in);
}

void
awg_encap_worker(void *_sc)
{
	struct mbuf *m;
	struct awg_softc *sc = _sc;
	while ((m = awg_ring_dequeue(&sc->sc_encap_ring)) != NULL)
		awg_encap(sc, m);
}

void
awg_decap_worker(void *_sc)
{
	struct mbuf *m;
	struct awg_softc *sc = _sc;
	while ((m = awg_ring_dequeue(&sc->sc_decap_ring)) != NULL)
		awg_decap(sc, m);
}

void
awg_deliver_out(void *_peer)
{
	struct awg_peer		*peer = _peer;
	struct awg_softc		*sc = peer->p_sc;
	struct awg_endpoint	 endpoint;
	struct awg_tag		*t;
	struct mbuf		*m;
	int			 ret;

	awg_peer_get_endpoint(peer, &endpoint);

	while ((m = awg_queue_dequeue(&peer->p_encap_queue, &t)) != NULL) {
		/* t_mbuf will contain the encrypted packet */
		if (t->t_mbuf == NULL){
			counters_inc(sc->sc_if.if_counters, ifc_oerrors);
			m_freem(m);
			continue;
		}

		ret = awg_send(sc, &endpoint, t->t_mbuf);

		if (ret == 0) {
			awg_timers_event_any_authenticated_packet_traversal(
			    &peer->p_timers);
			awg_timers_event_any_authenticated_packet_sent(
			    &peer->p_timers);

			if (m->m_pkthdr.len != 0)
				awg_timers_event_data_sent(&peer->p_timers);
		} else if (ret == EADDRNOTAVAIL) {
			awg_peer_clear_src(peer);
			awg_peer_get_endpoint(peer, &endpoint);
		}

		m_freem(m);
	}
}

void
awg_deliver_in(void *_peer)
{
	struct awg_peer	*peer = _peer;
	struct awg_softc	*sc = peer->p_sc;
	struct awg_tag	*t;
	struct mbuf	*m;

	while ((m = awg_queue_dequeue(&peer->p_decap_queue, &t)) != NULL) {
		/* t_mbuf will contain the decrypted packet */
		if (t->t_mbuf == NULL) {
			counters_inc(sc->sc_if.if_counters, ifc_ierrors);
			m_freem(m);
			continue;
		}

		/* From here on m == t->t_mbuf */
		KASSERT(m == t->t_mbuf);

		awg_timers_event_any_authenticated_packet_received(
		    &peer->p_timers);
		awg_timers_event_any_authenticated_packet_traversal(
		    &peer->p_timers);

		if (m->m_pkthdr.len == 0) {
			m_freem(m);
			continue;
		}

#if NBPFILTER > 0
		if (sc->sc_if.if_bpf != NULL)
			bpf_mtap_af(sc->sc_if.if_bpf,
			    m->m_pkthdr.ph_family, m, BPF_DIRECTION_IN);
#endif

		NET_LOCK();
		if (m->m_pkthdr.ph_family == AF_INET)
			ipv4_input(&sc->sc_if, m, NULL);
#ifdef INET6
		else if (m->m_pkthdr.ph_family == AF_INET6)
			ipv6_input(&sc->sc_if, m, NULL);
#endif
		else
			panic("invalid ph_family");
		NET_UNLOCK();

		awg_timers_event_data_received(&peer->p_timers);
	}
}

int
awg_queue_in(struct awg_softc *sc, struct awg_peer *peer, struct mbuf *m)
{
	struct awg_ring		*parallel = &sc->sc_decap_ring;
	struct awg_queue		*serial = &peer->p_decap_queue;
	struct awg_tag		*t;

	mtx_enter(&serial->q_mtx);
	if (serial->q_list.ml_len < MAX_QUEUED_PKT) {
		ml_enqueue(&serial->q_list, m);
		mtx_leave(&serial->q_mtx);
	} else {
		mtx_leave(&serial->q_mtx);
		m_freem(m);
		return ENOBUFS;
	}

	mtx_enter(&parallel->r_mtx);
	if (parallel->r_tail - parallel->r_head < MAX_QUEUED_PKT) {
		parallel->r_buf[parallel->r_tail & MAX_QUEUED_PKT_MASK] = m;
		parallel->r_tail++;
		mtx_leave(&parallel->r_mtx);
	} else {
		mtx_leave(&parallel->r_mtx);
		t = awg_tag_get(m);
		t->t_done = 1;
		return ENOBUFS;
	}

	return 0;
}

void
awg_queue_out(struct awg_softc *sc, struct awg_peer *peer)
{
	struct awg_ring		*parallel = &sc->sc_encap_ring;
	struct awg_queue		*serial = &peer->p_encap_queue;
	struct mbuf_list 	 ml, ml_free;
	struct mbuf		*m;
	struct awg_tag		*t;
	int			 dropped;

	/*
	 * We delist all staged packets and then add them to the queues. This
	 * can race with awg_qstart when called from awg_send_keepalive, however
	 * awg_qstart will not race as it is serialised.
	 */
	mq_delist(&peer->p_stage_queue, &ml);
	ml_init(&ml_free);

	while ((m = ml_dequeue(&ml)) != NULL) {
		mtx_enter(&serial->q_mtx);
		if (serial->q_list.ml_len < MAX_QUEUED_PKT) {
			ml_enqueue(&serial->q_list, m);
			mtx_leave(&serial->q_mtx);
		} else {
			mtx_leave(&serial->q_mtx);
			ml_enqueue(&ml_free, m);
			continue;
		}

		mtx_enter(&parallel->r_mtx);
		if (parallel->r_tail - parallel->r_head < MAX_QUEUED_PKT) {
			parallel->r_buf[parallel->r_tail & MAX_QUEUED_PKT_MASK] = m;
			parallel->r_tail++;
			mtx_leave(&parallel->r_mtx);
		} else {
			mtx_leave(&parallel->r_mtx);
			t = awg_tag_get(m);
			t->t_done = 1;
		}
	}

	if ((dropped = ml_purge(&ml_free)) > 0)
		counters_add(sc->sc_if.if_counters, ifc_oqdrops, dropped);
}

struct mbuf *
awg_ring_dequeue(struct awg_ring *r)
{
	struct mbuf *m = NULL;
	mtx_enter(&r->r_mtx);
	if (r->r_head != r->r_tail) {
		m = r->r_buf[r->r_head & MAX_QUEUED_PKT_MASK];
		r->r_head++;
	}
	mtx_leave(&r->r_mtx);
	return m;
}

struct mbuf *
awg_queue_dequeue(struct awg_queue *q, struct awg_tag **t)
{
	struct mbuf *m;
	mtx_enter(&q->q_mtx);
	if ((m = q->q_list.ml_head) != NULL && (*t = awg_tag_get(m))->t_done)
		ml_dequeue(&q->q_list);
	else
		m = NULL;
	mtx_leave(&q->q_mtx);
	return m;
}

struct awg_noise_remote *
awg_remote_get(void *_sc, uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
	struct awg_peer	*peer;
	struct awg_softc	*sc = _sc;
	if ((peer = awg_peer_lookup(sc, public)) == NULL)
		return NULL;
	return &peer->p_remote;
}

uint32_t
awg_index_set(void *_sc, struct awg_noise_remote *remote)
{
	struct awg_peer	*peer;
	struct awg_softc	*sc = _sc;
	struct awg_index *index, *iter;
	uint32_t	 key;

	/*
	 * We can modify this without a lock as awg_index_set, awg_index_drop are
	 * guaranteed to be serialised (per remote).
	 */
	peer = CONTAINER_OF(remote, struct awg_peer, p_remote);
	index = SLIST_FIRST(&peer->p_unused_index);
	KASSERT(index != NULL);
	SLIST_REMOVE_HEAD(&peer->p_unused_index, i_unused_entry);

	index->i_value = remote;

	mtx_enter(&sc->sc_index_mtx);
assign_id:
	key = index->i_key = arc4random();
	key &= sc->sc_index_mask;
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == index->i_key)
			goto assign_id;

	LIST_INSERT_HEAD(&sc->sc_index[key], index, i_entry);

	mtx_leave(&sc->sc_index_mtx);

	/* Likewise, no need to lock for index here. */
	return index->i_key;
}

struct awg_noise_remote *
awg_index_get(void *_sc, uint32_t key0)
{
	struct awg_softc		*sc = _sc;
	struct awg_index		*iter;
	struct awg_noise_remote	*remote = NULL;
	uint32_t		 key = key0 & sc->sc_index_mask;

	mtx_enter(&sc->sc_index_mtx);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			remote = iter->i_value;
			break;
		}
	mtx_leave(&sc->sc_index_mtx);
	return remote;
}

void
awg_index_drop(void *_sc, uint32_t key0)
{
	struct awg_softc	*sc = _sc;
	struct awg_index	*iter;
	struct awg_peer	*peer = NULL;
	uint32_t	 key = key0 & sc->sc_index_mask;

	mtx_enter(&sc->sc_index_mtx);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			LIST_REMOVE(iter, i_entry);
			break;
		}
	mtx_leave(&sc->sc_index_mtx);

	/* We expect a peer */
	peer = CONTAINER_OF(iter->i_value, struct awg_peer, p_remote);
	KASSERT(peer != NULL);
	SLIST_INSERT_HEAD(&peer->p_unused_index, iter, i_unused_entry);
}

/*
 * Find the message type of an incoming datagram from its size, the S1-S4
 * prefixes and the H1-H4 ranges (DeterminePacketTypeAndPadding in
 * amneziawg-go). With header protection the type field is decrypted with
 * the first 4 key stream bytes; the caller decrypts the rest of the header
 * (msglen bytes after the prefix) with the same nonce.
 */
int
awg_classify(struct awg_softc *sc, struct mbuf *m, size_t *padding,
    size_t *msglen, uint8_t nonce[AWG_HPK_NONCE_LEN], int *hp)
{
	static const struct {
		int	type;
		size_t	size;
	} hs[] = {
		{ AWG_TYPE_INITIATION,	sizeof(struct awg_pkt_initiation) },
		{ AWG_TYPE_RESPONSE,	sizeof(struct awg_pkt_response) },
		{ AWG_TYPE_COOKIE,	sizeof(struct awg_pkt_cookie) },
	};
	struct awg_range	 h[4] = { sc->sc_awg_h1, sc->sc_awg_h2,
				    sc->sc_awg_h3, sc->sc_awg_h4 };
	size_t			 s[4] = { sc->sc_awg_s1, sc->sc_awg_s2,
				    sc->sc_awg_s3, sc->sc_awg_s4 };
	chacha_ctx		 ctx;
	uint8_t			*buf = mtod(m, uint8_t *);
	uint8_t			 hash[4] = { 0 };
	size_t			 len = m->m_pkthdr.len, i;
	uint32_t		 typ, mask;
	int			 trailers = sc->sc_awg_random_trailers;

	*hp = 0;
	if (sc->sc_awg_has_hpk && len >= AWG_HPK_NONCE_LEN) {
		memcpy(nonce, buf, AWG_HPK_NONCE_LEN);
		if ((*hp = awg_hp_init(sc, &ctx, nonce))) {
			chacha_encrypt_bytes(&ctx, hash, hash, sizeof(hash));
			explicit_bzero(&ctx, sizeof(ctx));
		}
	}
	memcpy(&mask, hash, sizeof(mask));

	for (i = 0; i < nitems(hs); i++) {
		if (!(len == s[i] + hs[i].size ||
		    (trailers && len > s[i] + hs[i].size)))
			continue;
		memcpy(&typ, buf + s[i], sizeof(typ));
		typ ^= mask;
		if (awg_range_contains(h[i], letoh32(typ))) {
			*padding = s[i];
			*msglen = hs[i].size;
			return hs[i].type;
		}
	}

	if (len >= s[3] + AWG_MIN_DATA_SIZE) {
		memcpy(&typ, buf + s[3], sizeof(typ));
		typ ^= mask;
		if (awg_range_contains(h[3], letoh32(typ))) {
			*padding = s[3];
			*msglen = sizeof(struct awg_pkt_data);
			return AWG_TYPE_DATA;
		}
	}
	return 0;
}

struct mbuf *
awg_input(void *_sc, struct mbuf *m, struct ip *ip, struct ip6_hdr *ip6,
    void *_uh, int hlen, struct netstack *ns)
{
	struct awg_pkt_data	*data;
	struct awg_noise_remote	*remote;
	struct awg_tag		*t;
	struct awg_softc		*sc = _sc;
	struct udphdr		*uh = _uh;
	chacha_ctx		 ctx;
	uint8_t			 nonce[AWG_HPK_NONCE_LEN];
	size_t			 padding, msglen;
	int			 type, hp;
	char			 ipaddr[INET6_ADDRSTRLEN];

	NET_ASSERT_LOCKED();

	if ((t = awg_tag_get(m)) == NULL) {
		m_freem(m);
		return NULL;
	}

	if (ip != NULL) {
		t->t_endpoint.e_remote.r_sa.sa_len = sizeof(struct sockaddr_in);
		t->t_endpoint.e_remote.r_sa.sa_family = AF_INET;
		t->t_endpoint.e_remote.r_sin.sin_port = uh->uh_sport;
		t->t_endpoint.e_remote.r_sin.sin_addr = ip->ip_src;
		t->t_endpoint.e_local.l_in = ip->ip_dst;
#ifdef INET6
	} else if (ip6 != NULL) {
		t->t_endpoint.e_remote.r_sa.sa_len = sizeof(struct sockaddr_in6);
		t->t_endpoint.e_remote.r_sa.sa_family = AF_INET6;
		t->t_endpoint.e_remote.r_sin6.sin6_port = uh->uh_sport;
		t->t_endpoint.e_remote.r_sin6.sin6_addr = ip6->ip6_src;
		t->t_endpoint.e_local.l_in6 = ip6->ip6_dst;
#endif
	} else {
		m_freem(m);
		return NULL;
	}

	/* m has a IP/IPv6 header of hlen length, we don't need it anymore. */
	m_adj(m, hlen);

	/*
	 * Ensure mbuf is contiguous over full length of packet. This is done
	 * so we can directly read the handshake values in awg_handshake, and so
	 * we can decrypt a transport packet by passing a single buffer to
	 * awg_noise_remote_decrypt in awg_decap.
	 */
	if ((m = m_pullup(m, m->m_pkthdr.len)) == NULL)
		return NULL;

	if ((type = awg_classify(sc, m, &padding, &msglen, nonce, &hp)) == 0) {
		counters_inc(sc->sc_if.if_counters, ifc_ierrors);
		m_freem(m);
		return NULL;
	}

	/* Strip the S1-S4 prefix and, for handshakes, any random trailer */
	m_adj(m, padding);
	if (type != AWG_TYPE_DATA && m->m_pkthdr.len > msglen)
		m_adj(m, -(int)(m->m_pkthdr.len - msglen));

	if (hp && awg_hp_init(sc, &ctx, nonce)) {
		chacha_encrypt_bytes(&ctx, mtod(m, uint8_t *),
		    mtod(m, uint8_t *), msglen);
		explicit_bzero(&ctx, sizeof(ctx));
	}

	t->t_type = type;
	if (type != AWG_TYPE_DATA) {
		if (mq_enqueue(&sc->sc_handshake_queue, m) != 0)
			AWGPRINTF(LOG_DEBUG, sc, NULL, "Dropping handshake"
			    "packet from %s\n",
			    sockaddr_ntop(&t->t_endpoint.e_remote.r_sa,
			        ipaddr, sizeof(ipaddr)));
		task_add(awg_handshake_taskq, &sc->sc_handshake);
	} else {
		data = mtod(m, struct awg_pkt_data *);

		if ((remote = awg_index_get(sc, data->r_idx)) != NULL) {
			t->t_peer = CONTAINER_OF(remote, struct awg_peer,
			    p_remote);
			t->t_mbuf = NULL;
			t->t_done = 0;

			if (awg_queue_in(sc, t->t_peer, m) != 0)
				counters_inc(sc->sc_if.if_counters,
				    ifc_iqdrops);
			task_add(awg_crypt_taskq, &sc->sc_decap);
		} else {
			counters_inc(sc->sc_if.if_counters, ifc_ierrors);
			m_freem(m);
		}
	}

	return NULL;
}

void
awg_qstart(struct ifqueue *ifq)
{
	struct ifnet		*ifp = ifq->ifq_if;
	struct awg_softc		*sc = ifp->if_softc;
	struct awg_peer		*peer;
	struct awg_tag		*t;
	struct mbuf		*m;
	SLIST_HEAD(,awg_peer)	 start_list;

	SLIST_INIT(&start_list);

	/*
	 * We should be OK to modify p_start_list, p_start_onlist in this
	 * function as there should only be one ifp->if_qstart invoked at a
	 * time.
	 */
	while ((m = ifq_dequeue(ifq)) != NULL) {
		t = awg_tag_get(m);
		peer = t->t_peer;
		if (mq_push(&peer->p_stage_queue, m) != 0)
			counters_inc(ifp->if_counters, ifc_oqdrops);
		if (!peer->p_start_onlist) {
			SLIST_INSERT_HEAD(&start_list, peer, p_start_list);
			peer->p_start_onlist = 1;
		}
	}
	SLIST_FOREACH(peer, &start_list, p_start_list) {
		if (awg_noise_remote_ready(&peer->p_remote) == 0)
			awg_queue_out(sc, peer);
		else
			awg_timers_event_want_initiation(&peer->p_timers);
		peer->p_start_onlist = 0;
	}
	task_add(awg_crypt_taskq, &sc->sc_encap);
}

int
awg_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *sa,
    struct rtentry *rt)
{
	struct awg_softc	*sc = ifp->if_softc;
	struct awg_peer	*peer;
	struct awg_tag	*t;
	int		 af, ret = EINVAL;

	NET_ASSERT_LOCKED();

	if ((t = awg_tag_get(m)) == NULL) {
		ret = ENOBUFS;
		goto error;
	}

	m->m_pkthdr.ph_family = sa->sa_family;
	if (sa->sa_family == AF_INET) {
		peer = awg_aip_lookup(sc->sc_aip4,
		    &mtod(m, struct ip *)->ip_dst);
#ifdef INET6
	} else if (sa->sa_family == AF_INET6) {
		peer = awg_aip_lookup(sc->sc_aip6,
		    &mtod(m, struct ip6_hdr *)->ip6_dst);
#endif
	} else {
		ret = EAFNOSUPPORT;
		goto error;
	}

#if NBPFILTER > 0
	if (sc->sc_if.if_bpf)
		bpf_mtap_af(sc->sc_if.if_bpf, sa->sa_family, m,
		    BPF_DIRECTION_OUT);
#endif

	if (peer == NULL) {
		ret = ENETUNREACH;
		goto error;
	}

	af = peer->p_endpoint.e_remote.r_sa.sa_family;
	if (af != AF_INET && af != AF_INET6) {
		AWGPRINTF(LOG_DEBUG, sc, NULL, "No valid endpoint has been "
		    "configured or discovered for peer %llu\n", peer->p_id);
		ret = EDESTADDRREQ;
		goto error;
	}

	if (m->m_pkthdr.ph_loopcnt++ > M_MAXLOOP) {
		AWGPRINTF(LOG_DEBUG, sc, NULL, "Packet looped\n");
		ret = ELOOP;
		goto error;
	}

	/*
	 * As we hold a reference to peer in the mbuf, we can't handle a
	 * delayed packet without doing some refcnting. If a peer is removed
	 * while a delayed holds a reference, bad things will happen. For the
	 * time being, delayed packets are unsupported. This may be fixed with
	 * another aip_lookup in awg_qstart, or refcnting as mentioned before.
	 */
	if (m->m_pkthdr.pf.delay > 0) {
		AWGPRINTF(LOG_DEBUG, sc, NULL, "PF delay unsupported\n");
		ret = EOPNOTSUPP;
		goto error;
	}

	t->t_peer = peer;
	t->t_mbuf = NULL;
	t->t_done = 0;
	t->t_mtu = ifp->if_mtu;

	/*
	 * We still have an issue with ifq that will count a packet that gets
	 * dropped in awg_qstart, or not encrypted. These get counted as
	 * ofails or oqdrops, so the packet gets counted twice.
	 */
	return if_enqueue(ifp, m);
error:
	counters_inc(ifp->if_counters, ifc_oerrors);
	m_freem(m);
	return ret;
}

/*
 * Validate the AmneziaWG parameters of a SIOCSAWG request against the
 * resulting interface state, before anything is changed.
 */
int
awg_ioctl_check(struct awg_softc *sc, struct awg_interface_io *io)
{
	struct awg_range	 h[4], *timing[5];
	uint16_t		 s[4];
	uint32_t		 f = io->i_flags;
	int			 i, j, version, legacy, has_hpk;

	version = f & AWG_INTERFACE_HAS_VERSION ?
	    io->i_version : sc->sc_awg_version;
	if (version != AWG_VERSION_LEGACY && version != AWG_VERSION_3_1)
		return EINVAL;
	legacy = version == AWG_VERSION_LEGACY;

	if (legacy && (f & AWG_INTERFACE_HAS_3_1))
		return EINVAL;

	if (f & AWG_INTERFACE_HAS_H) {
		h[0] = io->i_h1; h[1] = io->i_h2;
		h[2] = io->i_h3; h[3] = io->i_h4;
		for (i = 0; i < 4; i++)
			if (h[i].r_lo > h[i].r_hi ||
			    (legacy && h[i].r_lo != h[i].r_hi))
				return EINVAL;
	} else {
		h[0] = sc->sc_awg_h1; h[1] = sc->sc_awg_h2;
		h[2] = sc->sc_awg_h3; h[3] = sc->sc_awg_h4;
	}
	/* Ranges must not overlap or packets can't be told apart */
	if (!legacy)
		for (i = 0; i < 4; i++)
			for (j = i + 1; j < 4; j++)
				if (awg_range_overlap(h[i], h[j]))
					return EINVAL;

	timing[0] = &io->i_rekey_after_time;
	timing[1] = &io->i_rekey_timeout;
	timing[2] = &io->i_reject_after_time;
	timing[3] = &io->i_keepalive_timeout;
	timing[4] = &io->i_max_handshake_attempts;
	for (i = 0; i < 5; i++)
		if (f & (AWG_INTERFACE_HAS_REKEY_AFTER_TIME << i) &&
		    (timing[i]->r_lo > timing[i]->r_hi ||
		    timing[i]->r_hi > UINT16_MAX))
			return EINVAL;
	if (f & AWG_INTERFACE_HAS_CPA &&
	    (io->i_cpa.r_lo > io->i_cpa.r_hi || io->i_cpa.r_hi > UINT16_MAX))
		return EINVAL;

	/* HeaderProtectionKey takes its nonce from S1-S4 */
	s[0] = f & AWG_INTERFACE_HAS_S12 ? io->i_s1 : sc->sc_awg_s1;
	s[1] = f & AWG_INTERFACE_HAS_S12 ? io->i_s2 : sc->sc_awg_s2;
	s[2] = f & AWG_INTERFACE_HAS_S3 ? io->i_s3 : sc->sc_awg_s3;
	s[3] = f & AWG_INTERFACE_HAS_S4 ? io->i_s4 : sc->sc_awg_s4;
	if (f & AWG_INTERFACE_HAS_HPK) {
		for (has_hpk = 0, i = 0; i < AWG_HPK_LEN; i++)
			has_hpk |= io->i_hpk[i];
	} else {
		has_hpk = !legacy && sc->sc_awg_has_hpk;
	}
	if (has_hpk)
		for (i = 0; i < 4; i++)
			if (s[i] < AWG_HPK_NONCE_LEN)
				return EINVAL;

	return 0;
}

/* Drop everything AmneziaWG 3.1 when switching to the legacy protocol */
void
awg_reset_3_1(struct awg_softc *sc, struct awg_ispec old[AWG_ISPEC_COUNT])
{
	struct awg_peer	*peer;
	int		 i;

	sc->sc_awg_s3 = sc->sc_awg_s4 = 0;
	sc->sc_awg_h1.r_hi = sc->sc_awg_h1.r_lo;
	sc->sc_awg_h2.r_hi = sc->sc_awg_h2.r_lo;
	sc->sc_awg_h3.r_hi = sc->sc_awg_h3.r_lo;
	sc->sc_awg_h4.r_hi = sc->sc_awg_h4.r_lo;
	sc->sc_awg_has_hpk = 0;
	explicit_bzero(sc->sc_awg_hpk, sizeof(sc->sc_awg_hpk));
	bzero(&sc->sc_awg_cpa, sizeof(sc->sc_awg_cpa));
	bzero(&sc->sc_awg_rekey_after_time, sizeof(struct awg_range));
	bzero(&sc->sc_awg_rekey_timeout, sizeof(struct awg_range));
	bzero(&sc->sc_awg_reject_after_time, sizeof(struct awg_range));
	bzero(&sc->sc_awg_keepalive_timeout, sizeof(struct awg_range));
	bzero(&sc->sc_awg_max_handshake_attempts, sizeof(struct awg_range));
	sc->sc_awg_random_trailers = 0;
	sc->sc_awg_disable_cookies = 0;
	awg_update_noise_timings(sc);

	rw_enter_write(&sc->sc_ispec_lock);
	for (i = 0; i < AWG_ISPEC_COUNT; i++) {
		awg_ispec_free(&old[i]);
		old[i] = sc->sc_awg_ispec[i];
		bzero(&sc->sc_awg_ispec[i], sizeof(sc->sc_awg_ispec[i]));
	}
	rw_exit_write(&sc->sc_ispec_lock);

	TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
		mtx_enter(&peer->p_timers.t_mtx);
		peer->p_timers.t_persistent_keepalive_hi =
		    peer->p_timers.t_persistent_keepalive_interval;
		mtx_leave(&peer->p_timers.t_mtx);
	}
}

int
awg_ioctl_set(struct awg_softc *sc, struct awg_data_io *data)
{
	struct awg_interface_io	*iface_p, iface_o;
	struct awg_peer_io	*peer_p, peer_o;
	struct awg_aip_io	*aip_p, aip_o;

	struct awg_peer		*peer, *tpeer;
	struct awg_aip		*aip, *taip;

	in_port_t		 port;
	int			 rtable;

	uint8_t			 public[AWG_KEY_SIZE], private[AWG_KEY_SIZE];
	struct awg_ispec	 ispec[AWG_ISPEC_COUNT];
	char			*ispec_buf = NULL;
	size_t			 i, j;
	int			 ret, has_identity, legacy;

	if ((ret = suser(curproc)) != 0)
		return ret;

	bzero(ispec, sizeof(ispec));
	rw_enter_write(&sc->sc_lock);

	iface_p = data->awgd_interface;
	if ((ret = copyin(iface_p, &iface_o, sizeof(iface_o))) != 0)
		goto error;

	if ((ret = awg_ioctl_check(sc, &iface_o)) != 0)
		goto error;
	legacy = (iface_o.i_flags & AWG_INTERFACE_HAS_VERSION ?
	    iface_o.i_version : sc->sc_awg_version) == AWG_VERSION_LEGACY;

	/* I1-I5 are parsed up front, they are swapped in at the end */
	for (i = 0; i < AWG_ISPEC_COUNT; i++) {
		if (!(iface_o.i_flags & AWG_INTERFACE_HAS_I(i)))
			continue;
		if (ispec_buf == NULL)
			ispec_buf = malloc(AWG_ISPEC_MAXLEN, M_TEMP, M_WAITOK);
		if ((ret = copyinstr(iface_o.i_ispec[i], ispec_buf,
		    AWG_ISPEC_MAXLEN, NULL)) != 0)
			goto error;
		if ((ret = awg_ispec_parse(&ispec[i], ispec_buf)) != 0)
			goto error;
	}

	if (iface_o.i_flags & AWG_INTERFACE_REPLACE_PEERS)
		TAILQ_FOREACH_SAFE(peer, &sc->sc_peer_seq, p_seq_entry, tpeer)
			awg_peer_destroy(peer);

	if (iface_o.i_flags & AWG_INTERFACE_HAS_PRIVATE &&
	    (awg_noise_local_keys(&sc->sc_local, NULL, private) ||
	     timingsafe_bcmp(private, iface_o.i_private, AWG_KEY_SIZE))) {
		if (curve25519_generate_public(public, iface_o.i_private)) {
			if ((peer = awg_peer_lookup(sc, public)) != NULL)
				awg_peer_destroy(peer);
		}
		awg_noise_local_lock_identity(&sc->sc_local);
		has_identity = awg_noise_local_set_private(&sc->sc_local,
						       iface_o.i_private);
		TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
			awg_noise_remote_precompute(&peer->p_remote);
			awg_timers_event_reset_handshake_last_sent(&peer->p_timers);
			awg_noise_remote_expire_current(&peer->p_remote);
		}
		cookie_checker_update(&sc->sc_cookie,
				      has_identity == 0 ? public : NULL);
		awg_noise_local_unlock_identity(&sc->sc_local);
	}

	if (iface_o.i_flags & AWG_INTERFACE_HAS_PORT)
		port = htons(iface_o.i_port);
	else
		port = sc->sc_udp_port;

	if (iface_o.i_flags & AWG_INTERFACE_HAS_RTABLE)
		rtable = iface_o.i_rtable;
	else
		rtable = sc->sc_udp_rtable;

	if (port != sc->sc_udp_port || rtable != sc->sc_udp_rtable) {
		TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry)
			awg_peer_clear_src(peer);

		if (sc->sc_if.if_flags & IFF_RUNNING)
			if ((ret = awg_bind(sc, &port, &rtable)) != 0)
				goto error;

		sc->sc_udp_port = port;
		sc->sc_udp_rtable = rtable;
	}

	peer_p = &iface_p->i_peers[0];
	for (i = 0; i < iface_o.i_peers_count; i++) {
		if ((ret = copyin(peer_p, &peer_o, sizeof(peer_o))) != 0)
			goto error;

		/* Peer must have public key */
		if (!(peer_o.p_flags & AWG_PEER_HAS_PUBLIC))
			goto next_peer;

		/* PersistentKeepalive ranges are AmneziaWG 3.1 */
		if (peer_o.p_flags & AWG_PEER_HAS_PKA &&
		    peer_o.p_pka_hi != 0 && (peer_o.p_pka_hi < peer_o.p_pka ||
		    (legacy && peer_o.p_pka_hi != peer_o.p_pka))) {
			ret = EINVAL;
			goto error;
		}

		/* 0 = latest protocol, 1 = this protocol */
		if (peer_o.p_protocol_version != 0) {
			if (peer_o.p_protocol_version > 1) {
				ret = EPFNOSUPPORT;
				goto error;
			}
		}

		/* Get local public and check that peer key doesn't match */
		if (awg_noise_local_keys(&sc->sc_local, public, NULL) == 0 &&
		    bcmp(public, peer_o.p_public, AWG_KEY_SIZE) == 0)
			goto next_peer;

		/* Lookup peer, or create if it doesn't exist */
		if ((peer = awg_peer_lookup(sc, peer_o.p_public)) == NULL) {
			/* If we want to delete, no need creating a new one.
			 * Also, don't create a new one if we only want to
			 * update. */
			if (peer_o.p_flags & (AWG_PEER_REMOVE|AWG_PEER_UPDATE))
				goto next_peer;

			if ((peer = awg_peer_create(sc,
			    peer_o.p_public)) == NULL) {
				ret = ENOMEM;
				goto error;
			}
		}

		/* Remove peer and continue if specified */
		if (peer_o.p_flags & AWG_PEER_REMOVE) {
			awg_peer_destroy(peer);
			goto next_peer;
		}

		if (peer_o.p_flags & AWG_PEER_HAS_ENDPOINT)
			awg_peer_set_sockaddr(peer, &peer_o.p_sa);

		if (peer_o.p_flags & AWG_PEER_HAS_PSK)
			awg_noise_remote_set_psk(&peer->p_remote, peer_o.p_psk);

		if (peer_o.p_flags & AWG_PEER_HAS_PKA)
			awg_timers_set_persistent_keepalive(&peer->p_timers,
			    peer_o.p_pka, peer_o.p_pka_hi);

		if (peer_o.p_flags & AWG_PEER_REPLACE_AIPS) {
			LIST_FOREACH_SAFE(aip, &peer->p_aip, a_entry, taip) {
				awg_aip_remove(sc, peer, &aip->a_data);
			}
		}

		if (peer_o.p_flags & AWG_PEER_SET_DESCRIPTION)
			strlcpy(peer->p_description, peer_o.p_description,
			    IFDESCRSIZE);

		aip_p = &peer_p->p_aips[0];
		for (j = 0; j < peer_o.p_aips_count; j++) {
			if ((ret = copyin(aip_p, &aip_o, sizeof(aip_o))) != 0)
				goto error;
			ret = awg_aip_add(sc, peer, &aip_o);
			if (ret != 0)
				goto error;
			aip_p++;
		}

		peer_p = (struct awg_peer_io *)aip_p;
		continue;
next_peer:
		aip_p = &peer_p->p_aips[0];
		aip_p += peer_o.p_aips_count;
		peer_p = (struct awg_peer_io *)aip_p;
	}

	/* AmneziaWG obfuscation parameters, validated by awg_ioctl_check */
	if (iface_o.i_flags & AWG_INTERFACE_HAS_VERSION &&
	    iface_o.i_version != sc->sc_awg_version) {
		if (iface_o.i_version == AWG_VERSION_LEGACY)
			awg_reset_3_1(sc, ispec);
		sc->sc_awg_version = iface_o.i_version;
	}
	if (iface_o.i_flags & AWG_INTERFACE_HAS_JC) {
		sc->sc_awg_jc   = iface_o.i_jc;
		sc->sc_awg_jmin = iface_o.i_jmin;
		sc->sc_awg_jmax = iface_o.i_jmax;
	}
	if (iface_o.i_flags & AWG_INTERFACE_HAS_S12) {
		sc->sc_awg_s1 = iface_o.i_s1;
		sc->sc_awg_s2 = iface_o.i_s2;
	}
	if (iface_o.i_flags & AWG_INTERFACE_HAS_S3)
		sc->sc_awg_s3 = iface_o.i_s3;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_S4)
		sc->sc_awg_s4 = iface_o.i_s4;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_H) {
		sc->sc_awg_h1 = iface_o.i_h1;
		sc->sc_awg_h2 = iface_o.i_h2;
		sc->sc_awg_h3 = iface_o.i_h3;
		sc->sc_awg_h4 = iface_o.i_h4;
	}
	if (iface_o.i_flags & AWG_INTERFACE_HAS_HPK) {
		/* An all-zero key turns header protection off */
		sc->sc_awg_has_hpk = 0;
		memcpy(sc->sc_awg_hpk, iface_o.i_hpk, AWG_HPK_LEN);
		for (i = 0; i < AWG_HPK_LEN; i++)
			sc->sc_awg_has_hpk |= iface_o.i_hpk[i] != 0;
	}
	if (iface_o.i_flags & AWG_INTERFACE_HAS_CPA)
		sc->sc_awg_cpa = iface_o.i_cpa;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_REKEY_AFTER_TIME)
		sc->sc_awg_rekey_after_time = iface_o.i_rekey_after_time;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_REKEY_TIMEOUT)
		sc->sc_awg_rekey_timeout = iface_o.i_rekey_timeout;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_REJECT_AFTER_TIME)
		sc->sc_awg_reject_after_time = iface_o.i_reject_after_time;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_KEEPALIVE_TIMEOUT)
		sc->sc_awg_keepalive_timeout = iface_o.i_keepalive_timeout;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_MAX_HANDSHAKE_ATTEMPTS)
		sc->sc_awg_max_handshake_attempts =
		    iface_o.i_max_handshake_attempts;
	awg_update_noise_timings(sc);
	if (iface_o.i_flags & AWG_INTERFACE_HAS_TRAILERS)
		sc->sc_awg_random_trailers = iface_o.i_random_trailers != 0;
	if (iface_o.i_flags & AWG_INTERFACE_HAS_COOKIES)
		sc->sc_awg_disable_cookies = iface_o.i_disable_cookies != 0;
	for (i = 0; i < AWG_ISPEC_COUNT; i++) {
		struct awg_ispec tmp;

		if (!(iface_o.i_flags & AWG_INTERFACE_HAS_I(i)))
			continue;
		rw_enter_write(&sc->sc_ispec_lock);
		tmp = sc->sc_awg_ispec[i];
		sc->sc_awg_ispec[i] = ispec[i];
		rw_exit_write(&sc->sc_ispec_lock);
		ispec[i] = tmp;	/* freed below */
	}

error:
	rw_exit_write(&sc->sc_lock);
	for (i = 0; i < AWG_ISPEC_COUNT; i++)
		awg_ispec_free(&ispec[i]);
	if (ispec_buf != NULL)
		free(ispec_buf, M_TEMP, AWG_ISPEC_MAXLEN);
	explicit_bzero(&iface_o, sizeof(iface_o));
	explicit_bzero(&peer_o, sizeof(peer_o));
	explicit_bzero(&aip_o, sizeof(aip_o));
	explicit_bzero(public, sizeof(public));
	explicit_bzero(private, sizeof(private));
	return ret;
}

int
awg_ioctl_get(struct awg_softc *sc, struct awg_data_io *data)
{
	struct awg_interface_io	*iface_p, iface_o;
	struct awg_peer_io	*peer_p, peer_o;
	struct awg_aip_io	*aip_p;

	struct awg_peer		*peer;
	struct awg_aip		*aip;
	struct awg_ispec	*is;

	char			*ubuf[AWG_ISPEC_COUNT];
	size_t			 ulen[AWG_ISPEC_COUNT];
	size_t			 size, peer_count, aip_count, i;
	int			 ret = 0, is_suser = suser(curproc) == 0;

	size = sizeof(struct awg_interface_io);
	if (data->awgd_size < size && !is_suser)
		goto ret_size;

	iface_p = data->awgd_interface;
	bzero(&iface_o, sizeof(iface_o));

	rw_enter_read(&sc->sc_lock);

	if (sc->sc_udp_port != 0) {
		iface_o.i_port = ntohs(sc->sc_udp_port);
		iface_o.i_flags |= AWG_INTERFACE_HAS_PORT;
	}

	if (sc->sc_udp_rtable != 0) {
		iface_o.i_rtable = sc->sc_udp_rtable;
		iface_o.i_flags |= AWG_INTERFACE_HAS_RTABLE;
	}

	if (!is_suser)
		goto copy_out_iface;

	if (awg_noise_local_keys(&sc->sc_local, iface_o.i_public,
	    iface_o.i_private) == 0) {
		iface_o.i_flags |= AWG_INTERFACE_HAS_PUBLIC;
		iface_o.i_flags |= AWG_INTERFACE_HAS_PRIVATE;
	}

	size += sizeof(struct awg_peer_io) * sc->sc_peer_num;
	size += sizeof(struct awg_aip_io) * sc->sc_aip_num;
	if (data->awgd_size < size)
		goto unlock_and_ret_size;

	peer_count = 0;
	peer_p = &iface_p->i_peers[0];
	TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
		bzero(&peer_o, sizeof(peer_o));
		peer_o.p_flags = AWG_PEER_HAS_PUBLIC;
		peer_o.p_protocol_version = 1;

		if (awg_noise_remote_keys(&peer->p_remote, peer_o.p_public,
		    peer_o.p_psk) == 0)
			peer_o.p_flags |= AWG_PEER_HAS_PSK;

		if (awg_timers_get_persistent_keepalive(&peer->p_timers,
		    &peer_o.p_pka, &peer_o.p_pka_hi) == 0)
			peer_o.p_flags |= AWG_PEER_HAS_PKA;

		if (awg_peer_get_sockaddr(peer, &peer_o.p_sa) == 0)
			peer_o.p_flags |= AWG_PEER_HAS_ENDPOINT;

		mtx_enter(&peer->p_counters_mtx);
		peer_o.p_txbytes = peer->p_counters_tx;
		peer_o.p_rxbytes = peer->p_counters_rx;
		mtx_leave(&peer->p_counters_mtx);

		awg_timers_get_last_handshake(&peer->p_timers,
		    &peer_o.p_last_handshake);

		aip_count = 0;
		aip_p = &peer_p->p_aips[0];
		LIST_FOREACH(aip, &peer->p_aip, a_entry) {
			if ((ret = copyout(&aip->a_data, aip_p, sizeof(*aip_p))) != 0)
				goto unlock_and_ret_size;
			aip_p++;
			aip_count++;
		}
		peer_o.p_aips_count = aip_count;

		strlcpy(peer_o.p_description, peer->p_description, IFDESCRSIZE);

		if ((ret = copyout(&peer_o, peer_p, sizeof(peer_o))) != 0)
			goto unlock_and_ret_size;

		peer_p = (struct awg_peer_io *)aip_p;
		peer_count++;
	}
	iface_o.i_peers_count = peer_count;

	/* AmneziaWG obfuscation parameters */
	iface_o.i_version = sc->sc_awg_version;
	iface_o.i_jc   = sc->sc_awg_jc;
	iface_o.i_jmin = sc->sc_awg_jmin;
	iface_o.i_jmax = sc->sc_awg_jmax;
	iface_o.i_s1   = sc->sc_awg_s1;
	iface_o.i_s2   = sc->sc_awg_s2;
	iface_o.i_h1   = sc->sc_awg_h1;
	iface_o.i_h2   = sc->sc_awg_h2;
	iface_o.i_h3   = sc->sc_awg_h3;
	iface_o.i_h4   = sc->sc_awg_h4;
	iface_o.i_flags |= AWG_INTERFACE_HAS_VERSION|AWG_INTERFACE_HAS_JC|
	    AWG_INTERFACE_HAS_S12|AWG_INTERFACE_HAS_H;

	if (sc->sc_awg_version == AWG_VERSION_3_1) {
		iface_o.i_s3 = sc->sc_awg_s3;
		iface_o.i_s4 = sc->sc_awg_s4;
		if (sc->sc_awg_has_hpk) {
			memcpy(iface_o.i_hpk, sc->sc_awg_hpk, AWG_HPK_LEN);
			iface_o.i_flags |= AWG_INTERFACE_HAS_HPK;
		}
		iface_o.i_cpa = sc->sc_awg_cpa;
		iface_o.i_rekey_after_time = sc->sc_awg_rekey_after_time;
		iface_o.i_rekey_timeout = sc->sc_awg_rekey_timeout;
		iface_o.i_reject_after_time = sc->sc_awg_reject_after_time;
		iface_o.i_keepalive_timeout = sc->sc_awg_keepalive_timeout;
		iface_o.i_max_handshake_attempts =
		    sc->sc_awg_max_handshake_attempts;
		iface_o.i_random_trailers = sc->sc_awg_random_trailers;
		iface_o.i_disable_cookies = sc->sc_awg_disable_cookies;
		iface_o.i_flags |= AWG_INTERFACE_HAS_S3|AWG_INTERFACE_HAS_S4|
		    AWG_INTERFACE_HAS_CPA|AWG_INTERFACE_HAS_REKEY_AFTER_TIME|
		    AWG_INTERFACE_HAS_REKEY_TIMEOUT|
		    AWG_INTERFACE_HAS_REJECT_AFTER_TIME|
		    AWG_INTERFACE_HAS_KEEPALIVE_TIMEOUT|
		    AWG_INTERFACE_HAS_MAX_HANDSHAKE_ATTEMPTS|
		    AWG_INTERFACE_HAS_TRAILERS|AWG_INTERFACE_HAS_COOKIES;

		/*
		 * I1-I5 go to the buffers passed in i_ispec, i_ispec_len
		 * returns the size needed.
		 */
		if ((ret = copyin(iface_p->i_ispec, ubuf, sizeof(ubuf))) != 0 ||
		    (ret = copyin(iface_p->i_ispec_len, ulen,
		    sizeof(ulen))) != 0)
			goto unlock_and_ret_size;
		rw_enter_read(&sc->sc_ispec_lock);
		for (i = 0; i < AWG_ISPEC_COUNT; i++) {
			is = &sc->sc_awg_ispec[i];
			iface_o.i_ispec[i] = ubuf[i];
			iface_o.i_ispec_len[i] = is->is_desc_size;
			if (is->is_desc == NULL)
				continue;
			iface_o.i_flags |= AWG_INTERFACE_HAS_I(i);
			if (ubuf[i] != NULL && ulen[i] >= is->is_desc_size &&
			    (ret = copyout(is->is_desc, ubuf[i],
			    is->is_desc_size)) != 0)
				break;
		}
		rw_exit_read(&sc->sc_ispec_lock);
		if (ret != 0)
			goto unlock_and_ret_size;
	}

copy_out_iface:
	ret = copyout(&iface_o, iface_p, sizeof(iface_o));
unlock_and_ret_size:
	rw_exit_read(&sc->sc_lock);
	explicit_bzero(&iface_o, sizeof(iface_o));
	explicit_bzero(&peer_o, sizeof(peer_o));
ret_size:
	data->awgd_size = size;
	return ret;
}

int
awg_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifreq	*ifr = (struct ifreq *) data;
	struct awg_softc	*sc = ifp->if_softc;
	int		 ret = 0;

	switch (cmd) {
	case SIOCSAWG:
		NET_UNLOCK();
		ret = awg_ioctl_set(sc, (struct awg_data_io *) data);
		NET_LOCK();
		break;
	case SIOCGAWG:
		NET_UNLOCK();
		ret = awg_ioctl_get(sc, (struct awg_data_io *) data);
		NET_LOCK();
		break;
	/* Interface IOCTLs */
	case SIOCSIFADDR:
		SET(ifp->if_flags, IFF_UP);
		/* FALLTHROUGH */
	case SIOCSIFFLAGS:
		if (ISSET(ifp->if_flags, IFF_UP))
			ret = awg_up(sc);
		else
			awg_down(sc);
		break;
	case SIOCSIFMTU:
		/* Arbitrary limits */
		if (ifr->ifr_mtu <= 0 || ifr->ifr_mtu > 9000)
			ret = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	default:
		ret = ENOTTY;
	}

	return ret;
}

int
awg_up(struct awg_softc *sc)
{
	struct awg_peer	*peer;
	int		 ret = 0;

	NET_ASSERT_LOCKED();
	/*
	 * We use IFF_RUNNING as an exclusive access here. We also may want
	 * an exclusive sc_lock as awg_bind may write to sc_udp_port. We also
	 * want to drop NET_LOCK as we want to call socreate, sobind, etc. Once
	 * solock is no longer === NET_LOCK, we may be able to avoid this.
	 */
	if (!ISSET(sc->sc_if.if_flags, IFF_RUNNING)) {
		SET(sc->sc_if.if_flags, IFF_RUNNING);
		NET_UNLOCK();

		rw_enter_write(&sc->sc_lock);
		/*
		 * If we successfully bind the socket, then enable the timers
		 * for the peer. This will send all staged packets and a
		 * keepalive if necessary.
		 */
		ret = awg_bind(sc, &sc->sc_udp_port, &sc->sc_udp_rtable);
		if (ret == 0) {
			TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
				awg_timers_enable(&peer->p_timers);
				awg_queue_out(sc, peer);
			}
		}
		rw_exit_write(&sc->sc_lock);

		NET_LOCK();
		if (ret != 0)
			CLR(sc->sc_if.if_flags, IFF_RUNNING);
	}
	return ret;
}

void
awg_down(struct awg_softc *sc)
{
	struct awg_peer	*peer;

	NET_ASSERT_LOCKED();
	if (!ISSET(sc->sc_if.if_flags, IFF_RUNNING))
		return;
	CLR(sc->sc_if.if_flags, IFF_RUNNING);
	NET_UNLOCK();

	/*
	 * We only need a read lock here, as we aren't writing to anything
	 * that isn't granularly locked.
	 */
	rw_enter_read(&sc->sc_lock);
	TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
		mq_purge(&peer->p_stage_queue);
		awg_timers_disable(&peer->p_timers);
	}

	taskq_barrier(awg_handshake_taskq);
	TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
		awg_noise_remote_clear(&peer->p_remote);
		awg_timers_event_reset_handshake_last_sent(&peer->p_timers);
	}

	awg_unbind(sc);
	rw_exit_read(&sc->sc_lock);
	NET_LOCK();
}

int
awg_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet		*ifp;
	struct awg_softc		*sc;
	struct awg_noise_upcall	 local_upcall;

	KERNEL_ASSERT_LOCKED();

	if (awg_counter == 0) {
		awg_handshake_taskq = taskq_create("awg_handshake",
		    2, IPL_NET, TASKQ_MPSAFE);
		awg_crypt_taskq = taskq_create("awg_crypt",
		    ncpus, IPL_NET, TASKQ_MPSAFE);

		if (awg_handshake_taskq == NULL || awg_crypt_taskq == NULL) {
			if (awg_handshake_taskq != NULL)
				taskq_destroy(awg_handshake_taskq);
			if (awg_crypt_taskq != NULL)
				taskq_destroy(awg_crypt_taskq);
			awg_handshake_taskq = NULL;
			awg_crypt_taskq = NULL;
			return ENOTRECOVERABLE;
		}
	}
	awg_counter++;

	if ((sc = malloc(sizeof(*sc), M_DEVBUF, M_NOWAIT | M_ZERO)) == NULL)
		goto ret_00;

	local_upcall.u_arg = sc;
	local_upcall.u_remote_get = awg_remote_get;
	local_upcall.u_index_set = awg_index_set;
	local_upcall.u_index_drop = awg_index_drop;

	TAILQ_INIT(&sc->sc_peer_seq);

	/* sc_if is initialised after everything else */
	arc4random_buf(&sc->sc_secret, sizeof(sc->sc_secret));

	rw_init(&sc->sc_lock, "awg");
	awg_noise_local_init(&sc->sc_local, &local_upcall);
	if (cookie_checker_init(&sc->sc_cookie, &awg_ratelimit_pool) != 0)
		goto ret_01;
	sc->sc_udp_port = 0;
	sc->sc_udp_rtable = 0;

	/*
	 * AmneziaWG defaults (all zero = standard WireGuard behaviour),
	 * legacy protocol until awgversion 3.1 is set.
	 */
	sc->sc_awg_version = AWG_VERSION_LEGACY;
	sc->sc_awg_jc   = 0;  sc->sc_awg_jmin = 0;  sc->sc_awg_jmax = 0;
	sc->sc_awg_s1   = 0;  sc->sc_awg_s2   = 0;
	sc->sc_awg_s3   = 0;  sc->sc_awg_s4   = 0;
	sc->sc_awg_h1.r_lo = sc->sc_awg_h1.r_hi = 1;
	sc->sc_awg_h2.r_lo = sc->sc_awg_h2.r_hi = 2;
	sc->sc_awg_h3.r_lo = sc->sc_awg_h3.r_hi = 3;
	sc->sc_awg_h4.r_lo = sc->sc_awg_h4.r_hi = 4;
	rw_init(&sc->sc_ispec_lock, "awg_ispec");

	rw_init(&sc->sc_so_lock, "awg_so");
	sc->sc_so4 = NULL;
#ifdef INET6
	sc->sc_so6 = NULL;
#endif

	sc->sc_aip_num = 0;
	rw_init(&sc->sc_aip_lock, "awgaip");
	if ((sc->sc_aip4 = art_alloc(32)) == NULL)
		goto ret_02;
#ifdef INET6
	if ((sc->sc_aip6 = art_alloc(128)) == NULL)
		goto ret_03;
#endif

	rw_init(&sc->sc_peer_lock, "awg_peer");
	sc->sc_peer_num = 0;
	if ((sc->sc_peer = hashinit(HASHTABLE_PEER_SIZE, M_DEVBUF,
	    M_NOWAIT, &sc->sc_peer_mask)) == NULL)
		goto ret_04;

	mtx_init(&sc->sc_index_mtx, IPL_NET);
	if ((sc->sc_index = hashinit(HASHTABLE_INDEX_SIZE, M_DEVBUF,
	    M_NOWAIT, &sc->sc_index_mask)) == NULL)
		goto ret_05;

	task_set(&sc->sc_handshake, awg_handshake_worker, sc);
	mq_init(&sc->sc_handshake_queue, MAX_QUEUED_HANDSHAKES, IPL_NET);

	task_set(&sc->sc_encap, awg_encap_worker, sc);
	task_set(&sc->sc_decap, awg_decap_worker, sc);

	bzero(&sc->sc_encap_ring, sizeof(sc->sc_encap_ring));
	mtx_init(&sc->sc_encap_ring.r_mtx, IPL_NET);
	bzero(&sc->sc_decap_ring, sizeof(sc->sc_decap_ring));
	mtx_init(&sc->sc_decap_ring.r_mtx, IPL_NET);

	/* We've setup the softc, now we can setup the ifnet */
	ifp = &sc->sc_if;
	ifp->if_softc = sc;

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "awg%d", unit);

	ifp->if_mtu = DEFAULT_MTU;
	ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_NOARP;
	ifp->if_xflags = IFXF_CLONED | IFXF_MPSAFE;
	ifp->if_txmit = 64; /* Keep our workers active for longer. */

	ifp->if_ioctl = awg_ioctl;
	ifp->if_qstart = awg_qstart;
	ifp->if_output = awg_output;

	ifp->if_type = IFT_WIREGUARD;
	ifp->if_rtrequest = p2p_rtrequest;

	if_counters_alloc(ifp);
	if_attach(ifp);
	if_alloc_sadl(ifp);

#if NBPFILTER > 0
	bpfattach(&ifp->if_bpf, ifp, DLT_LOOP, sizeof(uint32_t));
#endif

	AWGPRINTF(LOG_INFO, sc, NULL, "Interface created\n");

	return 0;
ret_05:
	hashfree(sc->sc_peer, HASHTABLE_PEER_SIZE, M_DEVBUF);
ret_04:
#ifdef INET6
	free(sc->sc_aip6, M_RTABLE, sizeof(*sc->sc_aip6));
ret_03:
#endif
	free(sc->sc_aip4, M_RTABLE, sizeof(*sc->sc_aip4));
ret_02:
	cookie_checker_deinit(&sc->sc_cookie);
ret_01:
	free(sc, M_DEVBUF, sizeof(*sc));
ret_00:
	return ENOBUFS;
}
int
awg_clone_destroy(struct ifnet *ifp)
{
	struct awg_softc	*sc = ifp->if_softc;
	struct awg_peer	*peer, *tpeer;
	int		 i;

	KERNEL_ASSERT_LOCKED();

	rw_enter_write(&sc->sc_lock);
	TAILQ_FOREACH_SAFE(peer, &sc->sc_peer_seq, p_seq_entry, tpeer)
		awg_peer_destroy(peer);
	rw_exit_write(&sc->sc_lock);

	awg_unbind(sc);
	if_detach(ifp);

	awg_counter--;
	if (awg_counter == 0) {
		KASSERT(awg_handshake_taskq != NULL && awg_crypt_taskq != NULL);
		taskq_destroy(awg_handshake_taskq);
		taskq_destroy(awg_crypt_taskq);
		awg_handshake_taskq = NULL;
		awg_crypt_taskq = NULL;
	}

	AWGPRINTF(LOG_INFO, sc, NULL, "Interface destroyed\n");

	hashfree(sc->sc_index, HASHTABLE_INDEX_SIZE, M_DEVBUF);
	hashfree(sc->sc_peer, HASHTABLE_PEER_SIZE, M_DEVBUF);
#ifdef INET6
	free(sc->sc_aip6, M_RTABLE, sizeof(*sc->sc_aip6));
#endif
	free(sc->sc_aip4, M_RTABLE, sizeof(*sc->sc_aip4));
	cookie_checker_deinit(&sc->sc_cookie);
	for (i = 0; i < AWG_ISPEC_COUNT; i++)
		awg_ispec_free(&sc->sc_awg_ispec[i]);
	explicit_bzero(sc->sc_awg_hpk, sizeof(sc->sc_awg_hpk));
	free(sc, M_DEVBUF, sizeof(*sc));
	return 0;
}

void
awgattach(int nawg)
{
#ifdef AWGTEST
	awg_noise_test();
#endif
	if_clone_attach(&awg_cloner);

	pool_init(&awg_aip_pool, sizeof(struct awg_aip), 0,
			IPL_NET, 0, "awgaip", NULL);
	pool_init(&awg_peer_pool, sizeof(struct awg_peer), 0,
			IPL_NET, 0, "awgpeer", NULL);
	pool_init(&awg_ratelimit_pool, sizeof(struct ratelimit_entry), 0,
			IPL_NET, 0, "awgratelimit", NULL);
}
