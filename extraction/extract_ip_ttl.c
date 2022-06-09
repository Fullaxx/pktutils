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

#include "mypcap.h"
#include "pcap_reader.h"
#include "pcap_writer.h"

#ifdef TIMING_STATS
extern unsigned long g_haystack_pktcount;
#include "timing_stats.h"
#endif

// The list of needles that we want to extract
unsigned char g_ipttl_a[256];

static void import_ipttl_list(char *list)
{
	char *token, *saveptr;
	unsigned char ttl;

	token = strtok_r(list, ",", &saveptr);
	while(token) {
		ttl = atoi(token);
		g_ipttl_a[ttl] = 1;
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
		fprintf(stderr, "%s: <IP TTL LIST> <NEEDLE> <HAYSTACK>\n", argv[0]);
		exit(1);
	}

	memset(&g_ipttl_a[0], 0, sizeof(g_ipttl_a));
	argone = strdup(argv[1]);
	import_ipttl_list(argv[1]);
	setup_output(argv[2], argv[3]);

#ifdef TIMING_STATS
	start_the_clock();
#endif

	i=2;
	while(++i < argc) {
		// Search the Haystack for Needles ...
		printf("Searching %s for IP TTL(s) %s ...\n", argv[i], argone);
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
