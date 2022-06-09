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

#ifndef __MYPCAP_H__
#define __MYPCAP_H__

#include <stdio.h>
#include <stdint.h>

#define PF_NSTS		(0x00000001)	// Set nanosecond timestamps
#define PF_APPEND	(0x00000002)	// Set append mode

#define PCAP_MAGIC_US	(0xA1B2C3D4)
#define PCAP_MAGIC_NS	(0xA1B23C4D)

typedef struct pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;	/* gmt to local correction; this is always 0 */
	uint32_t sigfigs;	/* accuracy of timestamps; this is always 0 */
	uint32_t snaplen;	/* max length saved portion of each pkt */
	uint32_t linktype;	/* data link type (LINKTYPE_*) */
} __attribute__ ((packed)) file_hdr_t;

/*
https://wiki.wireshark.org/Development/LibpcapFileFormat

ts_sec: the date and time when this packet was captured.
This value is in seconds since January 1, 1970 00:00:00 GMT;
this is also known as a UN*X time_t.
You can use the ANSI C time() function from time.h to get this value,
but you might use a more optimized way to get this timestamp value.
If this timestamp isn't based on GMT (UTC),
use thiszone from the global header for adjustments.

ts_usec: in regular pcap files,
the microseconds when this packet was captured, as an offset to ts_sec.
In nanosecond-resolution files, this is, instead,
the nanoseconds when the packet was captured, as an offset to ts_sec
Beware: this value shouldn't reach 1 second
(in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000);
in this case ts_sec must be increased instead!

incl_len: the number of bytes of packet data actually captured and saved in the file.
This value should never become larger than orig_len or the snaplen value of the global header.

orig_len: the length of the packet as it appeared on the network when it was captured.
If incl_len and orig_len differ, the actually saved packet size was limited by snaplen. 
*/

/* "libpcap" record header. */
typedef struct pcap_pkt_header {
    uint32_t sec;		/* timestamp seconds */
    uint32_t frac;		/* timestamp us/ns */
    uint32_t incl_len;	/* number of octets of packet saved in file */
    uint32_t orig_len;	/* actual length of packet */
} __attribute__ ((packed)) ptk_hdr_t;

typedef struct mypcap {
	FILE *pcap_file;
	char pcap_filename[1024+1];
	int32_t pcap_linktype;
	int32_t pcap_ns_res;
	uint64_t pcap_pktcount;
} mypcap_t;

// Get the linktype from a PCAP file
int mypcap_get_linktype(char *);

// Get the packet time resolution from a PCAP
int mypcap_is_nsts(char *);

mypcap_t* mypcap_open(char *, int, unsigned int);

// Add a packet to the PCAP file, using a TS created in this function call
int mypcap_add_pkt_now(mypcap_t *, unsigned char *, unsigned int);

// Add a packet to the PCAP file, using the TS values provided
int mypcap_add_pkt_us(mypcap_t *, unsigned char *, unsigned int, long, long);
int mypcap_add_pkt_ns(mypcap_t *, unsigned char *, unsigned int, long, long);

void mypcap_close(mypcap_t *);

#endif
