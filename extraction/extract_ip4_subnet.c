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
#include <arpa/inet.h>		// inet_pton()

#include "mypcap.h"
#include "pcap_reader.h"
#include "pcap_writer.h"

#ifdef TIMING_STATS
extern unsigned long g_haystack_pktcount;
#include "timing_stats.h"
#endif

// The IP4 CIDR that we want to extract
unsigned int g_cidr = 0;
unsigned int g_mask = 0;

static unsigned int create_mask(int maskbits)
{
	int i;
	unsigned int mask = 0;
	for(i=0; i<32; i++) {
		if(i < maskbits) {
			mask |= 1<<(31-i);
		}
	}
	return mask;
}

static void import_ip4_subnet(const char *cidr)
{
	int z, maskbits;
	unsigned int ip4;
	char *slash;

	slash = strchr(cidr, '/');
	if(!slash) {
		fprintf(stderr, "%s not in CIDR notation!\n", cidr);
		fprintf(stderr, "i.e.     10.0.0.0/8)\n");
		fprintf(stderr, "i.e.  172.16.0.0/12)\n");
		fprintf(stderr, "i.e. 192.168.0.0/16)\n");
		fprintf(stderr, "i.e. 75.75.75.75/30)\n");
		exit(1);
	}

	*slash = 0;
	maskbits = atoi(slash+1);

	// Save our IP4 address in network order
	z = inet_pton(AF_INET, cidr, &ip4);
	if(z != 1) {
		fprintf(stderr, "inet_pton(%s) failed!\n", cidr);
		exit(1);
	}

	g_mask = htonl(create_mask(maskbits));
	g_cidr = ip4 & g_mask;
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
		fprintf(stderr, "%s: <IP4 SUBNET> <NEEDLE> <HAYSTACK>\n", argv[0]);
		exit(1);
	}

	argone = strdup(argv[1]);
	import_ip4_subnet(argv[1]);
	setup_output(argv[2], argv[3]);

#ifdef TIMING_STATS
	start_the_clock();
#endif

	i=2;
	while(++i < argc) {
		// Search the Haystack for Needles ...
		printf("Searching %s for %s ...\n", argv[i], argone);
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
