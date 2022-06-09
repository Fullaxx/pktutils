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
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mypcap.h"

static int file_exists(char *fname)
{
	struct stat sb;
	if(stat(fname, &sb) == -1) { return 0; }
	if((sb.st_mode & S_IFMT) == S_IFREG) { return 1; }
	return 0;
}

int mypcap_get_linktype(char *filename)
{
	int retval = 0;
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
	if(r < sizeof(pcap_hdr)) { retval = -2; }

	// Get the linktype
	if(retval == 0) {
		retval = pcap_hdr.linktype;
	}

	fclose(file);
	return retval;
}

int mypcap_is_nsts(char *filename)
{
	FILE *file;
	size_t r;
	int retval = 0;
	struct pcap_file_header pcap_hdr;

	file = fopen(filename, "r");
	if(!file) {
		fprintf(stderr, "fopen(%s, r) failed!\n", filename);
		return -1;
	}

	// Read File Header
	r = fread(&pcap_hdr, 1, sizeof(pcap_hdr), file);
	if(r < sizeof(pcap_hdr)) { retval = -2; }

	// Does this pcap have nanosecond precision timestamps?
	if(retval == 0) {
		if(pcap_hdr.magic == PCAP_MAGIC_NS) { retval = 1; }
	}

	fclose(file);
	return retval;
}

mypcap_t* mypcap_open(char *filename, int linktype, unsigned int flags)
{
	size_t z;
	int write_file_header;
	int new_file, ns, append;
	struct pcap_file_header h;
	FILE *th;
	char *fopen_mode;
	mypcap_t *p;

	// Initialize variables
	p = NULL;
	new_file = 1;
	write_file_header = 1;
	fopen_mode = "w";

	// Configure our PCAP
	ns		= (flags &   PF_NSTS);
	append	= (flags & PF_APPEND);
	if(append) { fopen_mode = "a"; }
	if(file_exists(filename)) { new_file = 0; }
	if((new_file == 0) && append) { write_file_header = 0; }

	// If we are going to append data to a PCAP,
	// MAKE SURE we get the pkt time resolution correct
	// by pulling it out of the PCAP we are going to append data to
	if(write_file_header == 0) {
		ns = mypcap_is_nsts(filename);
		if(ns < 0) { return NULL; }
	}

	// Open our file
	th = fopen(filename, fopen_mode);
	if(!th) { return NULL; }

	// Allocate PCAP resources
	p = calloc(1, sizeof(mypcap_t));
	p->pcap_file = th;
	snprintf(p->pcap_filename, sizeof(p->pcap_filename), "%s", filename);
	p->pcap_linktype = linktype;
	p->pcap_ns_res = ns;

	// Write file header
	if(write_file_header) {
		if(ns) { h.magic = PCAP_MAGIC_NS; }
		else { h.magic = PCAP_MAGIC_US; }
		h.version_major = 2;
		h.version_minor = 4;
		h.thiszone = 0;
		h.sigfigs = 0;
		h.snaplen = 262144;
		h.linktype = linktype;

		z = fwrite(&h, 1, sizeof(h), p->pcap_file);
		if(z != sizeof(h)) {
			fprintf(stderr, "fwrite(h) failed!\n");
			free(p);
			p = NULL;
		}
	}

	return p;
}

static int mypcap_add_pkt(mypcap_t *p, unsigned char *data, unsigned int bytes, struct timeval *tsus, struct timespec *tsns)
{
	size_t z;
	ptk_hdr_t h;

	//packet header
	h.sec = h.frac = 0;
	if(p->pcap_ns_res) {	//IF PCAP IS NSEC
		if(tsns) {
			h.sec = tsns->tv_sec;
			h.frac = tsns->tv_nsec;
		} else if(tsus) {
			h.sec = tsus->tv_sec;
			h.frac = (tsus->tv_usec)*1000;
		}
	} else {	//IF PCAP IS USEC
		if(tsus) {
			h.sec = tsus->tv_sec;
			h.frac = tsus->tv_usec;
		} else if(tsns) {
			h.sec = tsns->tv_sec;
			h.frac = (tsns->tv_nsec)/1000;
		}
	}

	h.incl_len = bytes;
	h.orig_len = bytes;
	z = fwrite(&h, 1, sizeof(h), p->pcap_file);
	if(z != sizeof(h)) {
		fprintf(stderr, "fwrite(h) failed!\n");
		return 1;
	}

	//packet data
	z = fwrite(data, 1, bytes, p->pcap_file);
	if(z != bytes) {
		fprintf(stderr, "fwrite(bytes) failed!\n");
		return 2;
	}

	p->pcap_pktcount++;
	return 0;
}

int mypcap_add_pkt_now(mypcap_t *p, unsigned char *data, unsigned int bytes)
{
	struct timeval tsus;
	struct timespec tsns;

	if(p->pcap_ns_res) {
		memset(&tsns, 0, sizeof(tsns));
		clock_gettime(CLOCK_MONOTONIC, &tsns);
		return mypcap_add_pkt(p, data, bytes, NULL, &tsns);
	}

	if(p->pcap_ns_res == 0) {
		memset(&tsus, 0, sizeof(tsus));
		gettimeofday(&tsus, NULL);
		return mypcap_add_pkt(p, data, bytes, &tsus, NULL);
	}

	return -1;
}

// This function takes microseconds!
int mypcap_add_pkt_us(mypcap_t *p, unsigned char *data, unsigned int bytes, long seconds, long fraction)
{
	struct timeval pkttime;

	if(fraction > 999999) { return -2; }
	pkttime.tv_sec = seconds;
	pkttime.tv_usec = fraction;
	return mypcap_add_pkt(p, data, bytes, &pkttime, NULL);
}

// This function takes nanoseconds!
int mypcap_add_pkt_ns(mypcap_t *p, unsigned char *data, unsigned int bytes, long seconds, long fraction)
{
	struct timespec pkttime;

	if(fraction > 999999999) { return -2; }
	pkttime.tv_sec = seconds;
	pkttime.tv_nsec = fraction;
	return mypcap_add_pkt(p, data, bytes, NULL, &pkttime);
}

void mypcap_close(mypcap_t *p)
{
	fclose(p->pcap_file);
	free(p);
}
