#ifndef __PKT_UTILS_LAYER_TWO__
#define __PKT_UTILS_LAYER_TWO__

#include <arpa/inet.h>

#define	ETHERTYPE_PUP		(0x0200)
#define ETHERTYPE_SPRITE	(0x0500)
#define	ETHERTYPE_IP		(0x0800)
#define	ETHERTYPE_ARP		(0x0806)
#define	ETHERTYPE_WOL		(0x0842)
#define	ETHERTYPE_REVARP	(0x8035)
#define ETHERTYPE_AT		(0x809B)
#define ETHERTYPE_AARP		(0x80F3)
#define	ETHERTYPE_VLAN		(0x8100)
#define ETHERTYPE_IPX		(0x8137)
#define	ETHERTYPE_IPV6		(0x86dd)
#define ETH_P_PPP_DISC		(0x8863)
#define ETH_P_PPP_SES		(0x8864)
#define ETHERTYPE_LLDP		(0x88CC)
#define ETHERTYPE_LOOPBACK	(0x9000)

#define ETH_ALEN	(6)

typedef struct {
	uint8_t  ether_dhost[ETH_ALEN];
	uint8_t  ether_shost[ETH_ALEN];
	uint16_t ether_typelen;
} __attribute__ ((packed)) eth_t;
#define SIZE_ETHERNET (sizeof(eth_t))

#define ETH_TYPELEN(s) (ntohs(s->ether_typelen))

////////////////////////////////////////////////////////////////////////////////

#define PPP_IPV4	(0x0021)
#define PPP_IPV6	(0x0057)
#define PPP_CDP		(0x0207)
#define PPP_IPV4CP	(0x8021)
#define PPP_IPV6CP	(0x8057)
#define PPP_CCP		(0x80FD)
#define PPP_CCDP	(0x8207)
#define PPP_LCP		(0xC021)
#define PPP_PAP		(0xC023)
#define PPP_LQR		(0xC025)
#define PPP_CHAP	(0xC223)

typedef struct {
	uint8_t code;
	uint8_t identifier;
	uint16_t length;
	uint32_t magic;
	uint32_t data;
} __attribute__((packed)) ppp_lcp_t;
#define SIZE_PPP_LCP (sizeof(ppp_lcp_t))

#define PPP_LCP_CODE(s)  (      s->code)
#define PPP_LCP_ID(s)    (      s->identifier)
#define PPP_LCP_LEN(s)   (ntohs(s->length))
#define PPP_LCP_MAGIC(s) (ntohl(s->magic))
#define PPP_LCP_DATA(s)  (ntohl(s->data))

typedef struct {
	uint16_t protocol_id;
} __attribute__ ((packed)) ppp_proto_t;
#define SIZE_PPPPROTO (sizeof(ppp_proto_t))

#define PPPPROTO_PROTO(s) (ntohs(s->protocol_id))

typedef struct {
	uint8_t  info;		/* 4 bits version, 4 bits type */
	uint8_t  code;
	uint16_t id;
	uint16_t size;
} __attribute__ ((packed)) pppoe_sess_t;
#define SIZE_PPPOESESS (sizeof(pppoe_sess_t))

#define PPPOESESS_PSIZE(s) (ntohs(s->size))

typedef struct {
	uint8_t address;
	uint8_t control;
	uint16_t protocol;
} __attribute__((packed)) ppp_t;
#define SIZE_PPP (sizeof(ppp_t))

#define PPP_PROTO(s) (ntohs(s->protocol))

////////////////////////////////////////////////////////////////////////////////
// SSL Headers shamelessly ripped from libpcap

#ifndef SLL_ADDRLEN
#define SLL_ADDRLEN	8		/* length of address field */
#endif

typedef struct sll_header {
	uint16_t sll_pkttype;			/* packet type */
	uint16_t sll_hatype;			/* link-layer address type */
	uint16_t sll_halen;				/* link-layer address length */
	uint8_t  sll_addr[SLL_ADDRLEN];	/* link-layer address */
	uint16_t sll_protocol;			/* protocol */
}  __attribute__ ((packed)) sll_t;
#define SIZE_SLL (sizeof(sll_t))

#define SLL_PROTO(s) (ntohs(s->sll_protocol))

typedef struct sll2_header {
	uint16_t sll2_protocol;				/* protocol */
	uint16_t sll2_reserved_mbz;			/* reserved - must be zero */
	uint32_t sll2_if_index;				/* 1-based interface index */
	uint16_t sll2_hatype;				/* link-layer address type */
	uint8_t  sll2_pkttype;				/* packet type */
	uint8_t  sll2_halen;				/* link-layer address length */
	uint8_t  sll2_addr[SLL_ADDRLEN];	/* link-layer address */
}  __attribute__ ((packed)) sll2_t;
#define SIZE_SLL2 (sizeof(sll2_t))

#define SLL2_PROTO(s) (ntohs(s->sll2_protocol))

/*
 * The LINUX_SLL_ values for "sll_pkttype" and LINUX_SLL2_ values for
 * "sll2_pkttype"; these correspond to the PACKET_ values on Linux,
 * which are defined by a header under include/uapi in the current
 * kernel source, and are thus not going to change on Linux.  We
 * define them here so that they're available even on systems other
 * than Linux.
 */

#ifndef LINUX_SLL_HOST
#define LINUX_SLL_HOST		0
#endif

#ifndef LINUX_SLL_BROADCAST
#define LINUX_SLL_BROADCAST	1
#endif

#ifndef LINUX_SLL_MULTICAST
#define LINUX_SLL_MULTICAST	2
#endif

#ifndef LINUX_SLL_OTHERHOST
#define LINUX_SLL_OTHERHOST	3
#endif

#ifndef LINUX_SLL_OUTGOING
#define LINUX_SLL_OUTGOING	4
#endif

/*
 * The LINUX_SLL_ values for "sll_protocol" and LINUX_SLL2_ values for
 * "sll2_protocol"; these correspond to the ETH_P_ values on Linux, but
 * are defined here so that they're available even on systems other than
 * Linux.  We assume, for now, that the ETH_P_ values won't change in
 * Linux; if they do, then:
 *
 *	if we don't translate them in "pcap-linux.c", capture files
 *	won't necessarily be readable if captured on a system that
 *	defines ETH_P_ values that don't match these values;
 *
 *	if we do translate them in "pcap-linux.c", that makes life
 *	unpleasant for the BPF code generator, as the values you test
 *	for in the kernel aren't the values that you test for when
 *	reading a capture file, so the fixup code run on BPF programs
 *	handed to the kernel ends up having to do more work.
 *
 * Add other values here as necessary, for handling packet types that
 * might show up on non-Ethernet, non-802.x networks.  (Not all the ones
 * in the Linux "if_ether.h" will, I suspect, actually show up in
 * captures.)
 */

#ifndef LINUX_SLL_P_802_3
#define LINUX_SLL_P_802_3	0x0001	/* Novell 802.3 frames without 802.2 LLC header */
#endif

#ifndef LINUX_SLL_P_802_2
#define LINUX_SLL_P_802_2	0x0004	/* 802.2 frames (not D/I/X Ethernet) */
#endif

#ifndef LINUX_SLL_P_CAN
#define LINUX_SLL_P_CAN		0x000C	/* CAN frames, with SocketCAN pseudo-headers */
#endif

#ifndef LINUX_SLL_P_CANFD
#define LINUX_SLL_P_CANFD	0x000D	/* CAN FD frames, with SocketCAN pseudo-headers */
#endif

////////////////////////////////////////////////////////////////////////////////

typedef struct {
	uint8_t  rev;
	uint8_t  pad;
	uint16_t size;
} __attribute__ ((packed)) radiotap_t;
#define SIZE_RADIOTAP (sizeof(radiotap_t))

// This is LE b/c ???
#define RADIOTAP_HSIZE(s) ((s->size)+2)

////////////////////////////////////////////////////////////////////////////////

#endif
