/*	$OpenBSD: if_awg.h,v 1.1 2026/09/24 00:00:00 truebad0ur Exp $ */

/*
 * Copyright (C) 2026 Andrey Orekhov <pieceofcakecupofcoffee@gmail.com>
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>
 *
 * AmneziaWG kernel driver public interface for OpenBSD.
 * Based on if_wg.h from OpenBSD src/sys/net/.
 * Interface: awg0, awg1, ...
 * Ioctls: SIOCSAWG (223), SIOCGAWG (224)
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

#ifndef __IF_AWG_H__
#define __IF_AWG_H__

#include <net/if.h>
#include <netinet/in.h>

#define AWG_KEY_LEN 32

/*
 * 223/224 instead of the original 212/213: the structures below changed
 * with AWG 3.1 support, so a stale ifconfig(8) gets ENOTTY instead of
 * passing a mismatched layout to the kernel.
 */
#define SIOCSAWG _IOWR('i', 223, struct awg_data_io)
#define SIOCGAWG _IOWR('i', 224, struct awg_data_io)

/* Protocol versions selectable with awgversion */
#define AWG_VERSION_LEGACY	0	/* AmneziaWG < 3.1: Jc/Jmin/Jmax/S1/S2/H1-H4 */
#define AWG_VERSION_3_1		1	/* AmneziaWG >= 3.1 */

#define AWG_HPK_LEN		32	/* HeaderProtectionKey */
#define AWG_HPK_NONCE_LEN	12	/* S1-S4 must be at least this long */
#define AWG_ISPEC_COUNT		5	/* I1-I5 */
#define AWG_ISPEC_MAXLEN	8192	/* incl. NUL */

/* Inclusive range; lo == hi is a single value, 0-0 means unset */
struct awg_range {
	uint32_t		r_lo;
	uint32_t		r_hi;
};

#define a_ipv4	a_addr.addr_ipv4
#define a_ipv6	a_addr.addr_ipv6

struct awg_aip_io {
	sa_family_t	 a_af;
	int		 a_cidr;
	union awg_aip_addr {
		uint8_t			addr_bytes;
		struct in_addr		addr_ipv4;
		struct in6_addr		addr_ipv6;
	}		 a_addr;
};

#define AWG_PEER_HAS_PUBLIC		(1 << 0)
#define AWG_PEER_HAS_PSK		(1 << 1)
#define AWG_PEER_HAS_PKA		(1 << 2)
#define AWG_PEER_HAS_ENDPOINT		(1 << 3)
#define AWG_PEER_REPLACE_AIPS		(1 << 4)
#define AWG_PEER_REMOVE			(1 << 5)
#define AWG_PEER_UPDATE			(1 << 6)
#define AWG_PEER_SET_DESCRIPTION	(1 << 7)

#define p_sa	p_endpoint.sa_sa
#define p_sin	p_endpoint.sa_sin
#define p_sin6	p_endpoint.sa_sin6

struct awg_peer_io {
	int			p_flags;
	int			p_protocol_version;
	uint8_t			p_public[AWG_KEY_LEN];
	uint8_t			p_psk[AWG_KEY_LEN];
	uint16_t		p_pka;
	uint16_t		p_pka_hi;	/* 3.1: PersistentKeepalive range */
	union awg_peer_endpoint {
		struct sockaddr		sa_sa;
		struct sockaddr_in	sa_sin;
		struct sockaddr_in6	sa_sin6;
	}			p_endpoint;
	uint64_t		p_txbytes;
	uint64_t		p_rxbytes;
	struct timespec		p_last_handshake;
	char			p_description[IFDESCRSIZE];
	size_t			p_aips_count;
	struct awg_aip_io	p_aips[];
};

/* Flags for awg_interface_io.i_flags */
#define AWG_INTERFACE_HAS_PUBLIC	(1 << 0)
#define AWG_INTERFACE_HAS_PRIVATE	(1 << 1)
#define AWG_INTERFACE_HAS_PORT		(1 << 2)
#define AWG_INTERFACE_HAS_RTABLE	(1 << 3)
#define AWG_INTERFACE_REPLACE_PEERS	(1 << 4)
/* AmneziaWG-specific flags */
#define AWG_INTERFACE_HAS_JC		(1 << 5)  /* jc/jmin/jmax set */
#define AWG_INTERFACE_HAS_S12		(1 << 6)  /* s1/s2 set */
#define AWG_INTERFACE_HAS_H		(1 << 7)  /* h1/h2/h3/h4 set */
#define AWG_INTERFACE_HAS_VERSION	(1 << 8)
/* AmneziaWG 3.1 flags, rejected in legacy mode */
#define AWG_INTERFACE_HAS_S3		(1 << 9)
#define AWG_INTERFACE_HAS_S4		(1 << 10)
#define AWG_INTERFACE_HAS_HPK		(1 << 11) /* header protection key */
#define AWG_INTERFACE_HAS_CPA		(1 << 12) /* content padding addition */
#define AWG_INTERFACE_HAS_REKEY_AFTER_TIME (1 << 13)
#define AWG_INTERFACE_HAS_REKEY_TIMEOUT	(1 << 14)
#define AWG_INTERFACE_HAS_REJECT_AFTER_TIME (1 << 15)
#define AWG_INTERFACE_HAS_KEEPALIVE_TIMEOUT (1 << 16)
#define AWG_INTERFACE_HAS_MAX_HANDSHAKE_ATTEMPTS (1 << 17)
#define AWG_INTERFACE_HAS_TRAILERS	(1 << 18) /* random trailers */
#define AWG_INTERFACE_HAS_COOKIES	(1 << 19) /* disable cookies */
#define AWG_INTERFACE_HAS_I1		(1 << 20) /* I1..I5: HAS_I(0..4) */
#define AWG_INTERFACE_HAS_I(n)		(AWG_INTERFACE_HAS_I1 << (n))
#define AWG_INTERFACE_HAS_3_1		(0xffffU << 9)	  /* bits 9-24 */

struct awg_interface_io {
	uint32_t		i_flags;
	in_port_t		i_port;
	int			i_rtable;
	uint8_t			i_public[AWG_KEY_LEN];
	uint8_t			i_private[AWG_KEY_LEN];
	/* AmneziaWG obfuscation parameters */
	uint16_t		i_jc;		/* junk packet count */
	uint16_t		i_jmin;		/* junk packet min size (bytes) */
	uint16_t		i_jmax;		/* junk packet max size (bytes) */
	uint16_t		i_s1;		/* init packet junk prefix size */
	uint16_t		i_s2;		/* response packet junk prefix size */
	uint16_t		i_s3;		/* cookie packet junk prefix size */
	uint16_t		i_s4;		/* transport packet junk prefix size */
	struct awg_range	i_h1;		/* init magic header (default 1) */
	struct awg_range	i_h2;		/* response magic header (default 2) */
	struct awg_range	i_h3;		/* cookie magic header (default 3) */
	struct awg_range	i_h4;		/* transport magic header (default 4) */
	uint8_t			i_version;	/* AWG_VERSION_* */
	uint8_t			i_random_trailers;
	uint8_t			i_disable_cookies;
	uint8_t			i_hpk[AWG_HPK_LEN];
	struct awg_range	i_cpa;		/* ContentPaddingAddition */
	struct awg_range	i_rekey_after_time;
	struct awg_range	i_rekey_timeout;
	struct awg_range	i_reject_after_time;
	struct awg_range	i_keepalive_timeout;
	struct awg_range	i_max_handshake_attempts;
	/*
	 * I1-I5 tag strings, userland pointers. Set: NUL-terminated string.
	 * Get: buffer of i_ispec_len[n] bytes, filled when non-NULL.
	 */
	char			*i_ispec[AWG_ISPEC_COUNT];
	size_t			 i_ispec_len[AWG_ISPEC_COUNT];
	size_t			i_peers_count;
	struct awg_peer_io	i_peers[];
};

struct awg_data_io {
	char			 awgd_name[IFNAMSIZ];
	size_t			 awgd_size;
	struct awg_interface_io	*awgd_interface;
};

#endif /* __IF_AWG_H__ */
