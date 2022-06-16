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

#include "l3.h"
#include "mypcap.h"
#include "pcap_reader.h"
#include "pcap_writer.h"

#ifdef TIMING_STATS
extern unsigned long g_haystack_pktcount;
#include "timing_stats.h"
#endif

// The list of needles that we want to extract
unsigned char g_ipp_a[256];

static void import_ipp_list(char *list)
{
	char *token, *saveptr;
	int proto;

	token = strtok_r(list, ",", &saveptr);
	while(token) {
		proto = atoi(token);
		if((proto > 0) && (proto < 256)) {
			g_ipp_a[proto] = 1;
		} else {
			// EXPLICITLY MATCH IPPROTO = 0
			if(strcasecmp(token,    "ZERO") == 0) { g_ipp_a[0]               = 1; }
			if(strcasecmp(token,    "ICMP") == 0) { g_ipp_a[IPPROTO_ICMP]    = 1; }
			if(strcasecmp(token,    "IGMP") == 0) { g_ipp_a[IPPROTO_IGMP]    = 1; }
			if(strcasecmp(token,    "IPIP") == 0) { g_ipp_a[IPPROTO_IPIP]    = 1; }
			if(strcasecmp(token,     "TCP") == 0) { g_ipp_a[IPPROTO_TCP]     = 1; }
			if(strcasecmp(token,     "EGP") == 0) { g_ipp_a[IPPROTO_EGP]     = 1; }
			if(strcasecmp(token,     "PUP") == 0) { g_ipp_a[IPPROTO_PUP]     = 1; }
			if(strcasecmp(token,     "UDP") == 0) { g_ipp_a[IPPROTO_UDP]     = 1; }
			if(strcasecmp(token,     "IDP") == 0) { g_ipp_a[IPPROTO_IDP]     = 1; }
			if(strcasecmp(token,      "TP") == 0) { g_ipp_a[IPPROTO_TP]      = 1; }
			if(strcasecmp(token,    "DCCP") == 0) { g_ipp_a[IPPROTO_DCCP]    = 1; }
			if(strcasecmp(token,    "RSVP") == 0) { g_ipp_a[IPPROTO_RSVP]    = 1; }
			if(strcasecmp(token,     "GRE") == 0) { g_ipp_a[IPPROTO_GRE]     = 1; }
			if(strcasecmp(token,     "ESP") == 0) { g_ipp_a[IPPROTO_ESP]     = 1; }
			if(strcasecmp(token,      "AH") == 0) { g_ipp_a[IPPROTO_AH]      = 1; }
			if(strcasecmp(token,  "ICMPV6") == 0) { g_ipp_a[IPPROTO_ICMPV6]  = 1; }
			if(strcasecmp(token,     "MTP") == 0) { g_ipp_a[IPPROTO_MTP]     = 1; }
			if(strcasecmp(token,  "BEETPH") == 0) { g_ipp_a[IPPROTO_BEETPH]  = 1; }
			if(strcasecmp(token,   "ENCAP") == 0) { g_ipp_a[IPPROTO_ENCAP]   = 1; }
			if(strcasecmp(token,     "PIM") == 0) { g_ipp_a[IPPROTO_PIM]     = 1; }
			if(strcasecmp(token,    "COMP") == 0) { g_ipp_a[IPPROTO_COMP]    = 1; }
			if(strcasecmp(token,    "SCTP") == 0) { g_ipp_a[IPPROTO_SCTP]    = 1; }
			if(strcasecmp(token, "UDPLITE") == 0) { g_ipp_a[IPPROTO_UDPLITE] = 1; }
			if(strcasecmp(token,    "MPLS") == 0) { g_ipp_a[IPPROTO_MPLS]    = 1; }
			if(strcasecmp(token,     "RAW") == 0) { g_ipp_a[IPPROTO_RAW]     = 1; }
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
}

static void setup_output(char *output, char *first_haystack)
{
	int lt, ns, append;

	lt = mypcap_get_linktype(first_haystack);
	ns = mypcap_is_nsts(first_haystack);

	if(lt < 0) {
		fprintf(stderr, "mypcap_get_linktype(%s) failed!\n", first_haystack);
		exit(1);
	}

	if(ns < 0) {
		fprintf(stderr, "mypcap_is_nsts(%s)\n", first_haystack);
		exit(1);
	}

	append = 0;
	needle_open(output, lt, ns, append);
}

int main(int argc, char *argv[])
{
	int i;
	char *argone;

	if(argc < 4) {
		fprintf(stderr, "%s: <IP PROTO LIST> <NEEDLE> <HAYSTACK>\n", argv[0]);
		exit(1);
	}

	memset(&g_ipp_a[0], 0, sizeof(g_ipp_a));
	argone = strdup(argv[1]);
	import_ipp_list(argv[1]);
	setup_output(argv[2], argv[3]);

#ifdef TIMING_STATS
	start_the_clock();
#endif

	i=2;
	while(++i < argc) {
		// Search the Haystack for Needles ...
		printf("Searching %s for IP Proto(s) %s ...\n", argv[i], argone);
		process_pcapfile(argv[i]);
	}

#ifdef TIMING_STATS
	stop_the_clock();
	printf("%lu packets processed in %f seconds\n", g_haystack_pktcount, get_duration());
#endif

	printf("%lu packets extracted to %s\n", get_needle_count(), argv[2]);
	needle_close();
	free(argone);
	return 0;
}
