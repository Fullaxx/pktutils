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

#include "pcap_reader.h"

extern unsigned long g_haystack_pktcount;
extern unsigned long g_haystack_ethcount;
extern unsigned long g_haystack_ipv4count;
extern unsigned long g_haystack_ipv6count;
extern unsigned long g_haystack_tcpcount;
extern unsigned long g_haystack_udpcount;
extern unsigned long g_haystack_sctpcount;

#ifdef HIST_ETHPROTO
#define HISTMAX (65535)
#endif

#ifdef HIST_IPPROTO
#define HISTMAX (256)
#endif

#ifdef HIST_TCPPORT
#define HISTMAX (65535)
#endif

#ifdef HIST_UDPPORT
#define HISTMAX (65535)
#endif

#ifdef HIST_SCTPPORT
#define HISTMAX (65535)
#endif

unsigned long g_histogram[HISTMAX];

void hist_init(void)
{
	memset(&g_histogram[0], 0, sizeof(g_histogram));
}

void print_header(void)
{
#ifdef HIST_ETHPROTO
	printf("ETH PROTO,COUNT,%%\n");
#endif
#ifdef HIST_IPPROTO
	printf("IP PROTO,COUNT,%%\n");
#endif
#ifdef HIST_TCPPORT
	printf("TCP PORT,COUNT,%%\n");
#endif
#ifdef HIST_UDPPORT
	printf("UDP PORT,COUNT,%%\n");
#endif
#ifdef HIST_SCTPPORT
	printf("SCTP PORT,COUNT,%%\n");
#endif
}

void print_hist(void)
{
	int i;
	unsigned long pcount, total;
	double ratio;

#ifdef HIST_ETHPROTO
	total = (g_haystack_ethcount);
#endif
#ifdef HIST_IPPROTO
	total = (g_haystack_ipv4count+g_haystack_ipv6count);
#endif
#ifdef HIST_TCPPORT
	total = g_haystack_tcpcount;
#endif
#ifdef HIST_UDPPORT
	total = g_haystack_udpcount;
#endif
#ifdef HIST_SCTPPORT
	total = g_haystack_sctpcount;
#endif

	for(i=0; i<HISTMAX; i++) {
		pcount = g_histogram[i];
		if(pcount == 0) { continue; }

		if(total == 0) { ratio = 0.0; }
		else { ratio = (double)pcount / (double)total; }
#ifdef HIST_ETHPROTO
		printf("0x%04X,%lu,%2.2f%%\n", i, pcount, ratio*100.0);
#else
		printf("%d,%lu,%2.2f%%\n", i, pcount, ratio*100.0);
#endif
	}
}

int main(int argc, char *argv[])
{
	int i;

	if(argc < 2) {
		fprintf(stderr, "%s: <HAYSTACK>\n", argv[0]);
		exit(1);
	}

	i=0;
	hist_init();
	print_header();
	while(++i < argc) {
		// Search the Haystack for data to feed the histogram ...
		//fprintf(stderr, "Searching %s ...\n", argv[i]);
		process_pcapfile(argv[i]);
	}
	print_hist();

	return 0;
}
