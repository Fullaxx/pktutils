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

#include "mypcap.h"

// PCAP Handle (to store needles)
mypcap_t *g_ph = NULL;

void needle_open(char *filename, int lt, int ns, int app)
{
	unsigned int flags = 0;

	if(ns) { flags |= PF_NSTS; }
	if(app) { flags |= PF_APPEND; }
	g_ph = mypcap_open(filename, lt, flags);
	if(!g_ph) { fprintf(stderr, "pcap_open(%s) failed!\n", filename); exit(1); }
}

void needle_add_us(unsigned char *buf, int len, long sec, long frac)
{
	int z;
	z = mypcap_add_pkt_us(g_ph, buf, len, sec, frac);
	if(z != 0) {
		fprintf(stderr, "mypcap_add_pkt_us() failed!\n");
		exit(1);
	}
}

void needle_add_ns(unsigned char *buf, int len, long sec, long frac)
{
	int z;
	z = mypcap_add_pkt_ns(g_ph, buf, len, sec, frac);
	if(z != 0) {
		fprintf(stderr, "mypcap_add_pkt_ns() failed!\n");
		exit(1);
	}
}

unsigned long get_needle_count(void)
{
	return g_ph->pcap_pktcount;
}

void needle_close(void)
{
	if(g_ph) {
		mypcap_close(g_ph);
		g_ph = NULL;
	}
}
