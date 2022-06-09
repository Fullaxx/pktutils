#ifndef __PKT_UTILS_LAYER_THREE__
#define __PKT_UTILS_LAYER_THREE__

#include <arpa/inet.h>

typedef struct {
	uint8_t  info;		/* 4 bits version, 4 bits header size */
	uint8_t  tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t csum;
	uint32_t src;
	uint32_t dst;
} __attribute__ ((packed)) ipv4_t;
#define SIZE_IPV4 (sizeof(ipv4_t))

#define IPV4_VERS(s)   (     (s->info & 0xF0) >> 4)
#define IPV4_HSIZE(s)  (     (s->info & 0x0F) << 2) /* convert words to bytes */
#define IPV4_TOS(s)    (      s->tos)
#define IPV4_TOTLEN(s) (ntohs(s->tot_len))
#define IPV4_ID(s)     (ntohs(s->id))
#define IPV4_TTL(s)    (      s->ttl)
#define IPV4_PROTO(s)  (      s->proto)
#define IPV4_CSUM(s)   (ntohs(s->csum))
#define IPV4_SRC(s)    (ntohl(s->src))
#define IPV4_DST(s)    (ntohl(s->dst))

typedef struct {
	uint32_t info;			/* 4 bits version, 8 bits TC, 20 bits flow-ID */
	uint16_t size;			/* payload length */
	uint8_t  nxth;			/* next header */
	uint8_t  hlim;			/* hop limit */
	uint8_t  src[16];		/* source address */
	uint8_t  dst[16];		/* dest address */
} __attribute__ ((packed)) ipv6_t;
#define SIZE_IPV6 (sizeof(ipv6_t))

#define IPV6_VERS(s)  ((ntohl(s->info) & 0xF0000000) >> 28)
#define IPV6_TC(s)    ((ntohl(s->info) & 0x0FF00000) >> 20)
#define IPV6_FID(s)   ((ntohl(s->info) & 0x000FFFFF) >>  0)
#define IPV6_PSIZE(s) ( ntohs(s->size))
#define IPV6_NXTH(s)  (       s->nxth)
#define IPV6_HLIM(s)  (       s->hlim)

#endif
