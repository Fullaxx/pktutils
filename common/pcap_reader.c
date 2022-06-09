/*
	Copyright (C) 2022 Brett Kuskie <fullaxx@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; version 2 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef EXTRACTION
#include "pcap_writer.h"
#endif

#include "l1.h"
#include "l2.h"
#include "l3.h"
#include "l4.h"
#include "mypcap.h"

// Prototype
static int process_ipv4(unsigned char *buf, int len);

unsigned long g_haystack_pktcount = 0;
unsigned long g_haystack_llccount = 0;
unsigned long g_haystack_ethcount = 0;
unsigned long g_haystack_ipv4count = 0;
unsigned long g_haystack_ipv6count = 0;
unsigned long g_haystack_tcpcount = 0;
unsigned long g_haystack_udpcount = 0;
unsigned long g_haystack_sctpcount = 0;

#ifdef EXTRACT_ETHPROTO
extern unsigned char g_ethp_a[65536];
#endif

#ifdef EXTRACT_IPTTL
extern unsigned char g_ipttl_a[256];
#endif

#ifdef EXTRACT_IPPROTO
extern unsigned char g_ipp_a[256];
#endif

#ifdef EXTRACT_IP4ADDR
extern unsigned int g_ip4;
#endif

#ifdef EXTRACT_IP4SUBNET
extern unsigned int g_cidr;
extern unsigned int g_mask;
#endif

#if defined(EXTRACT_TCP) || defined(EXTRACT_UDP) || defined(EXTRACT_SCTP)
extern unsigned char g_port_a[65536];
#endif

#if defined(HIST_ETHPROTO) || defined(HIST_IPPROTO) || defined(HIST_TCPPORT) || defined(HIST_UDPPORT) || defined(HIST_SCTPPORT)
extern unsigned long g_histogram[];
#endif

static int process_icmp(unsigned char *buf, int len) { return 0; }
static int process_igmp(unsigned char *buf, int len) { return 0; }
static int process_tcp(unsigned char *buf, int len)
{
	tcp_t *tcp;
	unsigned char tcp_hsize;
	//unsigned char tcp_flags;
	unsigned short src, dst;
	//unsigned int seq, ack;
	//unsigned short win, csum;

	if(len < SIZE_TCP) { return 0; }
	tcp = (tcp_t *)buf;

	tcp_hsize = TCP_HSIZE(tcp);
	src = TCP_SRCP(tcp);
	dst = TCP_DSTP(tcp);
	//seq = ntohl(tcp->th_seq);
	//ack = ntohl(tcp->th_ack);
	//tcp_flags = tcp->th_flags;
	//win = ntohs(tcp->th_win);
	//csum = ntohs(tcp->th_sum);

#ifdef EXTRACT_TCP
	if((g_port_a[src]) || (g_port_a[dst])) { return 1; } else { return 0; }
#endif

#ifdef HIST_TCPPORT
	g_histogram[src]++;
	g_histogram[dst]++;
#endif

	//buf += tcp_hsize; len -= tcp_hsize;
	g_haystack_tcpcount++;
	return 0;
}

static int process_egp(unsigned char *buf, int len) { return 0; }
static int process_pup(unsigned char *buf, int len) { return 0; }
static int process_udp(unsigned char *buf, int len)
{
	udp_t *udp;
	unsigned short src, dst;
	//unsigned short psize, csum;

	if(len < SIZE_UDP) { return 0; }
	udp = (udp_t *)buf;

	src = UDP_SRCP(udp);
	dst = UDP_DSTP(udp);
	//psize = UDP_PSIZE(udp);
	//csum = UDP_CSUM(udp);

#ifdef EXTRACT_UDP
	if((g_port_a[src]) || (g_port_a[dst])) { return 1; } else { return 0; }
#endif

#ifdef HIST_UDPPORT
	g_histogram[src]++;
	g_histogram[dst]++;
#endif

	//buf += SIZE_UDP; len -= SIZE_UDP;
	//if(len < psize) { return 0; }
	g_haystack_udpcount++;
	return 0;
}

static int process_idp(unsigned char *buf, int len) { return 0; }
static int process_tp(unsigned char *buf, int len) { return 0; }
static int process_dccp(unsigned char *buf, int len) { return 0; }
static int process_rsvp(unsigned char *buf, int len) { return 0; }
static int process_gre(unsigned char *buf, int len) { return 0; }
static int process_esp(unsigned char *buf, int len) { return 0; }
static int process_ah(unsigned char *buf, int len) { return 0; }
static int process_icmpv6(unsigned char *buf, int len) { return 0; }
static int process_mtp(unsigned char *buf, int len) { return 0; }
static int process_beetph(unsigned char *buf, int len) { return 0; }
static int process_encap(unsigned char *buf, int len) { return 0; }
static int process_pim(unsigned char *buf, int len) { return 0; }
static int process_comp(unsigned char *buf, int len) { return 0; }

static int process_sctp(unsigned char *buf, int len)
{
	sctp_t *sctp;
	unsigned short src, dst;
	//unsigned short vtag, csum;

	if(len < SIZE_SCTP) { return 0; }
	sctp = (sctp_t *)buf;

	src = SCTP_SRCP(sctp);
	dst = SCTP_DSTP(sctp);
	//vtag = SCTP_VTAG(sctp);
	//csum = SCTP_CSUM(sctp);

#ifdef EXTRACT_SCTP
	if((g_port_a[src]) || (g_port_a[dst])) { return 1; } else { return 0; }
#endif

#ifdef HIST_SCTPPORT
	g_histogram[src]++;
	g_histogram[dst]++;
#endif

	//buf += SIZE_SCTP; len -= SIZE_SCTP;
	g_haystack_sctpcount++;
	return 0;
}

static int process_ipv6_mh(unsigned char *buf, int len) { return 0; }
static int process_mpls(unsigned char *buf, int len) { return 0; }

static int process_ipv6(unsigned char *buf, int len)
{
	int r;
	ipv6_t *ip6;
	//unsigned short psize;
	unsigned char hop_lim, next_hdr, ext_size;
	//char ip_src[INET6_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];

	if(len < SIZE_IPV6) { return 0; }
	ip6 = (ipv6_t *)buf;

	if(IPV6_VERS(ip6) != 6) { return 0; }
	//psize = IPV6_PSIZE(ip6);
	next_hdr = IPV6_NXTH(ip6);
	hop_lim = IPV6_HLIM(ip6);
	//inet_ntop(AF_INET6, &ip6->ip6_src, &ip_src[0], INET6_ADDRSTRLEN);
	//inet_ntop(AF_INET6, &ip6->ip6_dst, &ip_dst[0], INET6_ADDRSTRLEN);

	buf += SIZE_IPV6; len -= SIZE_IPV6;

	/* Handle Extentions */
	if(next_hdr == 0) { /* Hop-by-Hop */
		if(len < 2) { return 0; }
		next_hdr = buf[0];
		ext_size = buf[1];
		buf += (8 + ext_size); len -= (8 + ext_size);
		if(len < 1) { return 0; }
	}

#ifdef EXTRACT_IPTTL
	// Search for our specified TTL
	if(g_ipttl_a[hop_lim]) { return 1; } else { return 0; }
#endif

#ifdef EXTRACT_IPPROTO
	// Search for our specified IP Protocol
	if(g_ipp_a[next_hdr]) { return 1; } else { return 0; }
#endif

#ifdef HIST_IPPROTO
	g_histogram[next_hdr]++;
#endif

	r = 0;
	switch(next_hdr) {
		case IPPROTO_ICMP:    r = process_icmp(buf, len); break;
		case IPPROTO_IGMP:    r = process_igmp(buf, len); break;
		case IPPROTO_IPIP:    r = process_ipv4(buf, len); break;
		case IPPROTO_TCP:     r = process_tcp(buf, len); break;
		case IPPROTO_EGP:     r = process_egp(buf, len); break;
		case IPPROTO_PUP:     r = process_pup(buf, len); break;
		case IPPROTO_UDP:     r = process_udp(buf, len); break;
		case IPPROTO_IDP:     r = process_idp(buf, len); break;
		case IPPROTO_TP:      r = process_tp(buf, len); break;
		case IPPROTO_DCCP:    r = process_dccp(buf, len); break;
		case IPPROTO_IPV6:    r = process_ipv6(buf, len); break;
		case IPPROTO_RSVP:    r = process_rsvp(buf, len); break;
		case IPPROTO_GRE:     r = process_gre(buf, len); break;
		case IPPROTO_ESP:     r = process_esp(buf, len); break;
		case IPPROTO_AH:      r = process_ah(buf, len); break;
		case IPPROTO_ICMPV6:  r = process_icmpv6(buf, len); break;
		case IPPROTO_MTP:     r = process_mtp(buf, len); break;
		case IPPROTO_BEETPH:  r = process_beetph(buf, len); break;
		case IPPROTO_ENCAP:   r = process_encap(buf, len); break;
		case IPPROTO_PIM:     r = process_pim(buf, len); break;
		case IPPROTO_COMP:    r = process_comp(buf, len); break;
		case IPPROTO_SCTP:    r = process_sctp(buf, len); break;
		case IPPROTO_MH:      r = process_ipv6_mh(buf, len); break;
		case IPPROTO_UDPLITE: r = process_udp(buf, len); break;
		case IPPROTO_MPLS:    r = process_mpls(buf, len); break;
	}

	g_haystack_ipv6count++;
	return r;
}

static int process_ipv4(unsigned char *buf, int len)
{
	int r;
	ipv4_t *ip4;
	unsigned char ip_hsize, ip_ttl, ip_proto;

	if(len < SIZE_IPV4) { return 0; }
	ip4 = (ipv4_t *)buf;

	if(IPV4_VERS(ip4) != 4) { return 0; }
	ip_hsize = IPV4_HSIZE(ip4);
	if(ip_hsize < 20) { return 0; }
	if(len < ip_hsize) { return 0; }
	ip_ttl = IPV4_TTL(ip4);
	ip_proto = IPV4_PROTO(ip4);

#ifdef EXTRACT_IPTTL
	// Search for our specified TTL
	if(g_ipttl_a[ip_ttl]) { return 1; } else { return 0; }
#endif

#ifdef EXTRACT_IPPROTO
	// Search for our specified IP Protocol
	if(g_ipp_a[ip_proto]) { return 1; } else { return 0; }
#endif

#ifdef EXTRACT_IP4ADDR
	// Search for our specified IP4 address in network order
	if(ip4->src == g_ip4) { return 1; }
	if(ip4->dst == g_ip4) { return 1; }
	return 0;
#endif

#ifdef EXTRACT_IP4SUBNET
	// Search for any IP4 address in our specified CIDR block
	if((ip4->src & g_mask) == g_cidr) { return 1; }
	if((ip4->dst & g_mask) == g_cidr) { return 1; }
#endif

#ifdef HIST_IPPROTO
	g_histogram[ip_proto]++;
#endif

	buf += ip_hsize; len -= ip_hsize;

	r = 0;
	switch(ip_proto) {
		case IPPROTO_ICMP:    r = process_icmp(buf, len); break;
		case IPPROTO_IGMP:    r = process_igmp(buf, len); break;
		case IPPROTO_IPIP:    r = process_ipv4(buf, len); break;
		case IPPROTO_TCP:     r = process_tcp(buf, len); break;
		case IPPROTO_EGP:     r = process_egp(buf, len); break;
		case IPPROTO_PUP:     r = process_pup(buf, len); break;
		case IPPROTO_UDP:     r = process_udp(buf, len); break;
		case IPPROTO_IDP:     r = process_idp(buf, len); break;
		case IPPROTO_TP:      r = process_tp(buf, len); break;
		case IPPROTO_DCCP:    r = process_dccp(buf, len); break;
		case IPPROTO_IPV6:    r = process_ipv6(buf, len); break;
		case IPPROTO_RSVP:    r = process_rsvp(buf, len); break;
		case IPPROTO_GRE:     r = process_gre(buf, len); break;
		case IPPROTO_ESP:     r = process_esp(buf, len); break;
		case IPPROTO_AH:      r = process_ah(buf, len); break;
		case IPPROTO_ICMPV6:  r = process_icmpv6(buf, len); break;
		case IPPROTO_MTP:     r = process_mtp(buf, len); break;
		case IPPROTO_BEETPH:  r = process_beetph(buf, len); break;
		case IPPROTO_ENCAP:   r = process_encap(buf, len); break;
		case IPPROTO_PIM:     r = process_pim(buf, len); break;
		case IPPROTO_COMP:    r = process_comp(buf, len); break;
		case IPPROTO_SCTP:    r = process_sctp(buf, len); break;
		case IPPROTO_MH:      r = process_ipv6_mh(buf, len); break;
		case IPPROTO_UDPLITE: r = process_udp(buf, len); break;
		case IPPROTO_MPLS:    r = process_mpls(buf, len); break;
	}

	g_haystack_ipv4count++;
	return r;
}

static int process_cdp(unsigned char *buf, int len)
{
	return 0;
}

static int process_lldp(unsigned char *buf, int len)
{
	return 0;
}

static int process_llc(unsigned char *buf, int len, unsigned short llc_len)
{
	return 0;
}

static int process_sll(unsigned char *buf, int len)
{
	int r;
	unsigned short proto;
	sll_t *sll;

	if(len < SIZE_SLL) { return 0; }
	sll = (sll_t *)buf;
	proto = SLL_PROTO(sll);
	buf += SIZE_SLL; len -= SIZE_SLL;

	r = 0;
	if(proto == 0x0800) { r = process_ipv4(buf, len); }
	if(proto == 0x86DD) { r = process_ipv6(buf, len); }

	return r;
}

static int process_raw(unsigned char *buf, int len)
{
	int r;
	unsigned char ip_v;

	if(len < 20) { return 0; }

	r = 0;
	ip_v = (buf[0] & 0xF0) >> 4;
	if(ip_v == 4) { r = process_ipv4(buf, len); }
	if(ip_v == 6) { r = process_ipv6(buf, len); }

	return r;
}

static int process_lcp(unsigned char *buf, int len)
{
	ppp_lcp_t *lcp;
	unsigned short length;
	unsigned int magic, data;

	if(len < SIZE_PPP_LCP) { return 0; }
	lcp = (ppp_lcp_t *)buf;
	length = PPP_LCP_LEN(lcp);

	if(length >= 8) {
		magic = PPP_LCP_MAGIC(lcp);
	}
	if(length >= 12) {
		data = PPP_LCP_DATA(lcp);
	}

	return 0;
}

static int process_ipv4cp(unsigned char *buf, int len) { return 0; }
static int process_ipv6cp(unsigned char *buf, int len) { return 0; }
static int process_ccp(unsigned char *buf, int len) { return 0; }
static int process_pap(unsigned char *buf, int len) { return 0; }
static int process_lqr(unsigned char *buf, int len) { return 0; }
static int process_chap(unsigned char *buf, int len) { return 0; }

static int process_ppp_proto(unsigned char *buf, int len)
{
	int r;
	ppp_proto_t *ppp;
	unsigned short proto;

	if(len < SIZE_PPPPROTO) { return 0; }
	ppp = (ppp_proto_t *)buf;
	proto = PPPPROTO_PROTO(ppp);

#ifdef EXTRACT_PPPPROTO
	if(g_pppp_a[proto]) { return 1; } else { return 0; }
#endif

	buf += SIZE_PPPPROTO; len -= SIZE_PPPPROTO;

	r = 0;
	switch(proto) {
		case PPP_IPV4:		r = process_ipv4(buf, len); break;
		case PPP_IPV6:		r = process_ipv6(buf, len); break;
		case PPP_CDP:		r = process_cdp(buf, len); break;
		//case PPP_AT:		r = process_at(buf, len); break;
		//case PPP_IPX:		r = process_ipx(buf, len); break;
		//case PPP_MP:		r = process_mp(buf, len); break;
		case PPP_IPV4CP:	r = process_ipv4cp(buf, len); break;
		case PPP_IPV6CP:	r = process_ipv6cp(buf, len); break;
		case PPP_CCP:		r = process_ccp(buf, len); break;
		case PPP_LCP:		r = process_lcp(buf, len); break;
		case PPP_PAP:		r = process_pap(buf, len); break;
		case PPP_LQR:		r = process_lqr(buf, len); break;
		case PPP_CHAP:		r = process_chap(buf, len); break;
	}

	return r;
}

static int process_pppoe_disc(unsigned char *buf, int len) { return 0; }

static int process_pppoe_sess(unsigned char *buf, int len)
{
	int r;
	pppoe_sess_t *pppoe;
	unsigned short psize;

	if(len < SIZE_PPPOESESS) { return 0; }
	pppoe = (pppoe_sess_t *)buf;
	psize = PPPOESESS_PSIZE(pppoe);
	buf += SIZE_PPPOESESS; len -= SIZE_PPPOESESS;
	if(len < psize) { return 0; }

	r = 0;
	if(pppoe->code == 0x00) { r = process_ppp_proto(buf, len); }

	return r;
}

static int process_ppp(unsigned char *buf, int len)
{
	int r;
	ppp_t *ppp;
	unsigned short proto;

	if(len < SIZE_PPP) { return 0; }

	ppp = (ppp_t *)buf;
	proto = PPP_PROTO(ppp);

#ifdef EXTRACT_PPPPROTO
	if(g_pppp_a[proto]) { return 1; } else { return 0; }
#endif

	buf += SIZE_PPP; len -= SIZE_PPP;

	r = 0;
	switch(proto) {
		case PPP_IPV4:		r = process_ipv4(buf, len); break;
		case PPP_IPV6:		r = process_ipv6(buf, len); break;
		case PPP_CDP:		r = process_cdp(buf, len); break;
		case PPP_IPV4CP:	r = process_ipv4cp(buf, len); break;
		case PPP_IPV6CP:	r = process_ipv6cp(buf, len); break;
		case PPP_CCP:		r = process_ccp(buf, len); break;
		case PPP_LCP:		r = process_lcp(buf, len); break;
		case PPP_PAP:		r = process_pap(buf, len); break;
		case PPP_LQR:		r = process_lqr(buf, len); break;
		case PPP_CHAP:		r = process_chap(buf, len); break;
	}

	return r;
}

static int process_arp(unsigned char *buf, int len) { return 0; }
static int process_wol(unsigned char *buf, int len) { return 0; }
static int process_rarp(unsigned char *buf, int len) { return 0; }
static int process_vlan(unsigned char *buf, int len) { return 0; }
static int process_ipx(unsigned char *buf, int len) { return 0; }

static int process_eth(unsigned char *buf, int len)
{
	int r;
	eth_t *eth;
	unsigned short typelen;

	if(len < SIZE_ETHERNET) { return 0; }

#ifdef EXTRACT_ETHBCAST
	if(buf[0] & 0x01) { return 1; } else { return 0; }
#endif

	eth = (eth_t *)buf;
	typelen = ETH_TYPELEN(eth);

/*
	https://en.wikipedia.org/wiki/EtherType
	In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment, a unifying standard,
	IEEE 802.3x-1997, was introduced that required that EtherType values be greater than or equal to 1536 (0x0600).
	That value was chosen because the maximum length (MTU) of the data field of an Ethernet 802.3 frame is 1500 bytes.
	Thus, values of 1500 and below for this field indicate that the field is used as the size of the payload of the Ethernet frame
	while values of 1536 and above indicate that the field is used to represent an EtherType.
	The interpretation of values 1501–1535, inclusive, is undefined.
*/

/*
	https://wiki.wireshark.org/Ethernet
	Ethernet packets could have no more than 1500 bytes of user data,
	so the field is interpreted as a length field if it has a value <= 1500
	and a type field if it has a value > 1500.
*/

	if(typelen > 1500) {
		g_haystack_ethcount++;
#ifdef HIST_ETHPROTO
		g_histogram[typelen]++;
#endif
#ifdef EXTRACT_ETHPROTO
		if(g_ethp_a[typelen]) { return 1; } else { return 0; }
#endif
	} else {	// LLC
		g_haystack_llccount++;
#ifdef EXTRACT_ETHPROTO
		if(g_ethp_a[0]) { return 1; } else { return 0; }
#endif
	}

	buf += SIZE_ETHERNET; len -= SIZE_ETHERNET;

	r = 0;
	switch(typelen) {
		case ETHERTYPE_IP:
			r = process_ipv4(buf, len);
			break;
		case ETHERTYPE_ARP:
			r = process_arp(buf, len);
			break;
		case ETHERTYPE_WOL:
			r = process_wol(buf, len);
			break;
		case ETHERTYPE_REVARP:
			r = process_rarp(buf, len);
			break;
		case ETHERTYPE_VLAN:
			r = process_vlan(buf, len);
			break;
		case ETHERTYPE_IPX:
			r = process_ipx(buf, len);
			break;
		case ETHERTYPE_IPV6:
			r = process_ipv6(buf, len);
			break;
		case ETH_P_PPP_DISC:
			r = process_pppoe_disc(buf, len);
			break;
		case ETH_P_PPP_SES:
			r = process_pppoe_sess(buf, len);
			break;
		case ETHERTYPE_LLDP:
			r = process_lldp(buf, len);
			break;
		case PPP_IPV4CP:
			r = process_ipv4cp(buf, len);
			break;
		case PPP_IPV6CP:
			r = process_ipv6cp(buf, len);
			break;
		case PPP_LCP:
			r = process_lcp(buf, len);
			break;
		default:
			if(typelen <= 1500) {
				r = process_llc(buf, len, typelen);
			}
			break;
	}

	return r;
}

/*
static int process_wlan(unsigned char *buf, int len)
{
	unsigned char subtype, type, version, head;

	head = p->raw_pkt[offset];
	subtype = (head & 0xF0) >> 4;
	type = (head & 0x0C) >> 2;
	version = (head & 0x03);

	switch(type) {
		case WT_MGMT:
			printf("MGMT ");
			process_wlan_mgmt(p, user, offset, left, subtype);
			break;
		case WT_CTRL:
			printf("CTRL ");
			switch(subtype) {
				case WSC_BLK_ACK_REQ:	process_wlan_blk_ack_req(p, user, offset, left); break;
				case WSC_BLK_ACK:		process_wlan_blk_ack(p, user, offset, left); break;
				case WSC_RTS:			process_wlan_rts(p, user, offset, left); break;
				case WSC_CTS:			process_wlan_cts(p, user, offset, left); break;
				case WSC_ACK:			process_wlan_ack(p, user, offset, left); break;
			}
			break;
		case WT_DATA:
			printf("DATA ");
			break;
		case WT_WDS:
			printf("WDS?? ");
			break;
	}

	return 0;
}

static int process_radiotap(unsigned char *buf, int len)
{
	radiotap_t *radiotap;
	unsigned short radiotap_hsize;

	if(len < SIZE_RADIOTAP) { return 0; }

	radiotap = (radiotap_t *)buf;
	radiotap_hsize = RADIOTAP_HSIZE(radiotap);
	if(len < radiotap_hsize) { return 0; }
	buf += radiotap_hsize; len -= radiotap_hsize;

	return process_wlan(buf, len);
}
*/



int process_2_4(FILE *file, char *filename, unsigned int lt, int nsres)
{
	int save, retval;
	size_t r;
	ptk_hdr_t pkt_hdr;
	unsigned char buf[262144];

	retval = 0;

	// Loop over Packet Headers
	while( (r = fread(&pkt_hdr, 1, sizeof(pkt_hdr), file)) > 0 ) {
		//if(r == 0) break; //END OF FILE - checked in loop above
		if(r < sizeof(pkt_hdr)) {
			fprintf(stderr, "r=%u (expected %lu)\n", (unsigned int)r, sizeof(pkt_hdr));
			retval = -2;
			break;
		}
		/*if(v >= 1) printf("PCAP Pkt Header: %u %u %u %u\n",
					pkt_hdr.sec, pkt_hdr.frac, pkt_hdr.incl_len, pkt_hdr.incl_len);*/

		if(pkt_hdr.incl_len > sizeof(buf)) {
			fprintf(stderr, "pkt_hdr.incl_len(%u) > %lu\n", pkt_hdr.incl_len, sizeof(buf));
			retval = -2;
			break;
		}

		// Read Packet Data
		r = fread(&buf, 1, pkt_hdr.incl_len, file);
		if(r < pkt_hdr.incl_len) {
			fprintf(stderr, "r=%u (expected %u)\n", (unsigned int)r, pkt_hdr.incl_len);
			retval = -2;
			break;
		}
		/*if(v >= 1) {
			printf("PCAP Pkt Data: ");
			for(i=0; i<r; i++) printf("%02X", buf[i]);
			putchar('\n');
		}*/

		save = 0;
		g_haystack_pktcount++;
		switch(lt) {
			case DLT_EN10MB:
				save = process_eth(&buf[0], pkt_hdr.incl_len);
				break;
			case DLT_RAW:
			case LINKTYPE_RAW:
				save = process_raw(&buf[0], pkt_hdr.incl_len);
				break;
			case DLT_PPP:
				process_ppp(&buf[0], pkt_hdr.incl_len);
				break;
			/*case DLT_IEEE802_11:
				save = process_wlan(&buf[0], pkt_hdr.incl_len);
				break;*/
			case DLT_LINUX_SLL:
				save = process_sll(&buf[0], pkt_hdr.incl_len);
				break;
			/*case DLT_PRISM_HEADER:
				break;
			case DLT_AIRONET_HEADER:
				break;
			case DLT_IEEE802_11_RADIO:
				save = process_radiotap(&buf[0], pkt_hdr.incl_len);
				break;
			case DLT_IEEE802_11_RADIO_AVS:
				break;
			case DLT_USB_LINUX:
				break;
			case DLT_IEEE802_15_4_WITHFCS:
				break;
			case DLT_BLUETOOTH_HCI_H4_WITH_PHDR:
				break;
			case DLT_IEEE802_15_4_NONASK_PHY:
				break;*/
			case DLT_IPV4:
				save = process_ipv4(&buf[0], pkt_hdr.incl_len);
				break;
			case DLT_IPV6:
				save = process_ipv6(&buf[0], pkt_hdr.incl_len);
				break;
			/*case DLT_IEEE802_15_4_NOFCS:
				break;
			case DLT_SCTP:
				break;
			case DLT_USBPCAP:
				break;
			case DLT_NETLINK:
				break;
			case DLT_BLUETOOTH_LINUX_MONITOR:
				break;
			case DLT_BLUETOOTH_BREDR_BB:
				break;
			case DLT_BLUETOOTH_LE_LL_WITH_PHDR:
				break;
			case DLT_USB_DARWIN:
				break;
			case DLT_LINUX_SLL2:
				save = process_sll2(&buf[0], pkt_hdr.incl_len);
				break;
			case DLT_IEEE802_15_4_TAP:
				break;
			case DLT_Z_WAVE_SERIAL:
				break;
			case DLT_USB_2_0:
				break;*/
		}

#ifdef EXTRACTION
		if(save) {
			// Found a needle, save it in our new PCAP
			if(nsres) { needle_add_ns(&buf[0], pkt_hdr.incl_len, pkt_hdr.sec, pkt_hdr.frac); }
			else { needle_add_us(&buf[0], pkt_hdr.incl_len, pkt_hdr.sec, pkt_hdr.frac); }
		}
#endif

		if(feof(file)) { break; }
		//if(g_shutdown) break;
	}

	return retval;
}

int process_pcapfile(char *filename)
{
	int retval, nsres;
	size_t r;
	struct pcap_file_header pcap_hdr;
	FILE *file;

	file = fopen(filename, "r");
	if(!file) {
		fprintf(stderr, "fopen(%s, r) failed!\n", filename);
		return -1;
	}

	// Read File Header
	r = fread(&pcap_hdr, 1, sizeof(pcap_hdr), file);
	if(r < sizeof(pcap_hdr)) { return -2; }
	/*if(v >= 1) printf("PCAP File Header: %04X %u %u %d, %u %u %u\n",
		pcap_hdr.magic, pcap_hdr.version_major, pcap_hdr.version_minor,
		pcap_hdr.thiszone, pcap_hdr.sigfigs, pcap_hdr.snaplen, pcap_hdr.linktype);*/

	// Does this pcap have nanosecond precision timestamps?
	if(pcap_hdr.magic == PCAP_MAGIC_NS) { nsres = 1; }
	if(pcap_hdr.magic == PCAP_MAGIC_US) { nsres = 0; }

	if((pcap_hdr.version_major == 2) && (pcap_hdr.version_minor == 4)) {
		retval = process_2_4(file, filename, pcap_hdr.linktype, nsres);
	} else { retval = -3; }

	fclose(file);
	return retval;
}
