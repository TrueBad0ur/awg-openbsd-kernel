/*
 * AmneziaWG for OpenBSD — kernel driver public interface.
 * Based on if_wg.h by Jason A. Donenfeld and Matt Dunwoodie.
 *
 * Designed to be used by tools such as ifconfig(8) and awg(8).
 * Interface: awg0, awg1, ...
 * Ioctls: SIOCSAWG (212), SIOCGAWG (213)
 */

#ifndef __IF_AWG_H__
#define __IF_AWG_H__

#include <net/if.h>
#include <netinet/in.h>

#define AWG_KEY_LEN 32

#define SIOCSAWG _IOWR('i', 212, struct awg_data_io)
#define SIOCGAWG _IOWR('i', 213, struct awg_data_io)

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
	uint32_t		i_h1;		/* init magic header (default 1) */
	uint32_t		i_h2;		/* response magic header (default 2) */
	uint32_t		i_h3;		/* cookie magic header (default 3) */
	uint32_t		i_h4;		/* transport magic header (default 4) */
	size_t			i_peers_count;
	struct awg_peer_io	i_peers[];
};

struct awg_data_io {
	char			 wgd_name[IFNAMSIZ];
	size_t			 wgd_size;
	struct awg_interface_io	*wgd_interface;
};

#endif /* __IF_AWG_H__ */
