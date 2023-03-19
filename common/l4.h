#ifndef __PKT_UTILS_LAYER_FOUR__
#define __PKT_UTILS_LAYER_FOUR__

#include <arpa/inet.h>

//https://tools.ietf.org/html/rfc792
typedef struct {
	uint8_t  type;
	uint8_t  code;
	uint16_t sum;
	uint32_t content;
} __attribute__ ((packed)) icmp_t;
#define SIZE_ICMP (sizeof(icmp_t))

#define ICMP_TYPE(s) (      s->type)
#define ICMP_CODE(s) (      s->code)
#define ICMP_CSUM(s) (ntohs(s->sum))

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY (0)
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO (8)
#endif

typedef struct {
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack;
	uint8_t  hlres;
	uint8_t  flags;
	uint16_t win;
	uint16_t sum;
	uint16_t urp;
} __attribute__ ((packed)) tcp_t;
#define SIZE_TCP (sizeof(tcp_t))

#define TCP_SRCP(s)   (ntohs(s->src))
#define TCP_DSTP(s)   (ntohs(s->dst))
#define TCP_SEQ(s)    (ntohl(s->seq))
#define TCP_ACK(s)    (ntohl(s->ack))
#define TCP_HSIZE(s)  (     (s->hlres & 0xF0) >> 2) /* convert words to bytes */
#define TCP_FLAGS(s)  (      s->flags)
#define TCP_URGBIT(s) (TCP_FLAGS(s) & 0x20)
#define TCP_ACKBIT(s) (TCP_FLAGS(s) & 0x10)
#define TCP_PSHBIT(s) (TCP_FLAGS(s) & 0x08)
#define TCP_RSTBIT(s) (TCP_FLAGS(s) & 0x04)
#define TCP_SYNBIT(s) (TCP_FLAGS(s) & 0x02)
#define TCP_FINBIT(s) (TCP_FLAGS(s) & 0x01)
#define TCP_WIN(s)    (ntohs(s->win))
#define TCP_CSUM(s)   (ntohs(s->sum))
#define TCP_URGP(s)   (ntohs(s->urp))

typedef struct {
	uint16_t src;
	uint16_t dst;
	uint16_t size;
	uint16_t sum;
} __attribute__ ((packed)) udp_t;
#define SIZE_UDP (sizeof(udp_t))

#define UDP_SRCP(s)  (ntohs(s->src))
#define UDP_DSTP(s)  (ntohs(s->dst))
#define UDP_PSIZE(s) (ntohs(s->size))
#define UDP_CSUM(s)  (ntohs(s->sum))

typedef struct {
	uint16_t src;
	uint16_t dst;
	uint32_t vtag;
	uint32_t sum;
} __attribute__ ((packed)) sctp_t;
#define SIZE_SCTP (sizeof(sctp_t))

#define SCTP_SRCP(s)  (ntohs(s->src))
#define SCTP_DSTP(s)  (ntohs(s->dst))
#define SCTP_VTAG(s)  (ntohl(s->vtag))
#define SCTP_CSUM(s)  (ntohl(s->sum))

#endif
