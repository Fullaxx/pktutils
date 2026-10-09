# Coding style

This is the style pktutils is written in. It was measured from the code at commit 6da8ab3. Every code block below is copied from the source; short inline examples are trimmed to fit. New code should look like the code around it.

The style serves the goals in the [README](README.md):
- do one thing and do it very well;
- process large pcap sets quickly;
- no non-libc dependencies;
- easy to read, learn and modify.

## Files

- **Directories:**
  - `common/` holds the pcap reader, the pcap writer and the protocol headers.
  - `extraction/` holds the `pex_*` tools.
  - `histogram/` holds the `phist_*` tools.
  - `tests/` holds test helpers such as `mkpcap.py`. They are Python 3, use only the standard library, and follow PEP 8 (4-space indentation; lines up to 99 characters, as PEP 8 allows). The tools themselves stay C.
- **License header:** `.c` files and module headers start with the GPLv2 block, which is:
  - `Copyright (C) 2022 Brett Kuskie <fullaxx@gmail.com>`;
  - the "version 2 of the License" wording.

  The protocol headers `l1.h`–`l4.h` and `timing_stats.*` don't carry it.
- **Include order:** system headers come first in `<>`, then project headers in `""`:
  ```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <unistd.h>

  #include "mypcap.h"
  #include "pcap_reader.h"
  #include "pcap_writer.h"
  ```
- **Header guards:** `#ifndef __NAME_H__` / `#define __NAME_H__` / `#endif`. The protocol headers use `__PKT_UTILS_LAYER_ONE__` and so on.

## Indentation and spacing

- **Indentation:** tabs. Spaces appear only to line up columns, as in struct members and macro bodies.
- **Keywords:** no space between a keyword and its parenthesis: `if(`, `while(`, `for(`, `switch(`. The code has 170 `if(` and no `if (`.
- **Operators:**
  - binary operators are usually surrounded by spaces: `len < SIZE_TCP`, `buf += SIZE_SLL`;
  - loop counters are written tight: `i=2;`, `i<HISTMAX`.
- **Return and sizeof:** `return r;` without parentheses; `sizeof(x)` always with them.

## Braces

- **Functions:** the opening brace goes on its own line.
- **Control statements:** the opening brace stays on the same line, and `else` is written `} else {`.
- **Single-statement bodies:** they keep their braces, usually on one line:
  ```c
  if(len < SIZE_UDP) { return 0; }
  if((g_port_a[src]) || (g_port_a[dst])) { return 1; } else { return 0; }
  ```
- **Stub functions:** they fit on one line:
  ```c
  static int process_icmp(unsigned char *buf, int len) { return 0; }
  ```
- **Paired statements:** two statements that always go together share a line:
  ```c
  buf += SIZE_SLL; len -= SIZE_SLL;
  ```

## Declarations and types

- **Placement:** local variables are declared at the top of the function, before the first statement (C89 style), grouped by type.
- **Pointers:** the `*` binds to the name: `unsigned char *buf`, `mypcap_t *p`.
- **Types:**
  - wire-format structs use fixed-width types (`uint8_t`, `uint16_t`, `uint32_t`);
  - local variables use `unsigned char` / `unsigned short` / `unsigned int`;
  - counters are `unsigned long`, printed with `%lu`.
- **Scope:** functions used only inside one file are `static`.
- **Globals:**
  - start with `g_`;
  - filters are lookup tables indexed by the value being tested, which makes each test one array read:
    ```c
    // The list of needles that we want to extract
    unsigned char g_port_a[65536];
    ```

## Naming

| Thing | Convention | Example |
|---|---|---|
| Functions, variables | snake_case | `process_pcapfile`, `ip_hsize` |
| Typedef'd structs | `_t` suffix | `eth_t`, `ipv4_t`, `mypcap_t` |
| Macros | UPPER_SNAKE | `ETHERTYPE_IP`, `PF_NSTS` |
| Constant values (the project's own) | in parentheses, uppercase hex | `#define ETHERTYPE_IP (0x0800)` |
| Parsers | `process_<layer>` | `process_eth`, `process_ipv4`, `process_tcp` |
| Header sizes | `SIZE_<HDR>` | `#define SIZE_UDP (sizeof(udp_t))` |
| Field accessors | `<HDR>_<FIELD>(s)` | `#define UDP_SRCP(s) (ntohs(s->src))` |
| Programs | `pex_<filter>.exe`, `phist_<field>.exe` | `pex_tcp_port.exe`, `phist_ip_proto.exe` |

## Protocol headers (`common/l1.h`–`l4.h`)

Each header layer is three parts:
1. a packed struct of the on-wire layout;
2. a `SIZE_` macro;
3. accessor macros, aligned in a column, that do the byte-order conversion.

Call sites never call `ntohs`/`ntohl` themselves.
```c
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
```

Constants are aligned with tabs. The project's own constants are in parentheses (52 of them). Definitions taken from libpcap keep libpcap's bare form (all 29 bare ones are in `l1.h` and `l2.h`), are credited, and are wrapped in `#ifndef` so the system's value wins:
```c
#define	ETHERTYPE_IP		(0x0800)
#define	ETHERTYPE_ARP		(0x0806)

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
```

## Packet parsers (`common/pcap_reader.c`)

**Signature.** Every layer is `static int process_<layer>(unsigned char *buf, int len)`. It returns 1 when the packet matches the filter compiled into this binary, and 0 otherwise.

**Shape.** Every parser follows the same steps:
1. check the length;
2. cast to the header struct;
3. read fields through the accessor macros;
4. advance `buf` and `len` together;
5. hand the rest to the next layer;
6. return its result.
```c
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
```

**Dispatch.** When there are many next layers, a `switch` assigns `r`, one case per line:
```c
	r = 0;
	switch(ip_proto) {
		case IPPROTO_ICMP:    r = process_icmp(buf, len); break;
		case IPPROTO_IGMP:    r = process_igmp(buf, len); break;
```

**Match points.** Each tool is `pcap_reader.c` compiled with one `-D` (see `compile.sh`). An `#ifdef EXTRACT_*` block decides the match right where the field becomes known. An `#ifdef HIST_*` block counts the field into `g_histogram`. The `g_haystack_*count` counters give the histogram its totals.
```c
#ifdef EXTRACT_UDP
	if((g_port_a[src]) || (g_port_a[dst])) { return 1; } else { return 0; }
#endif

#ifdef HIST_UDPPORT
	g_histogram[src]++;
	g_histogram[dst]++;
#endif
```

**Stubs and parked code.** Layers that aren't parsed yet are one-line stubs that return 0. Fields that aren't used yet, and future cases, stay in the code as comments, so the next step is visible:
```c
	src = UDP_SRCP(udp);
	dst = UDP_DSTP(udp);
	//psize = UDP_PSIZE(udp);
	//csum = UDP_CSUM(udp);
```

## Tools (`extraction/`, `histogram/`)

`main()` follows a fixed sequence:
1. check `argc`; print the usage line to stderr and `exit(1)`;
2. parse the arguments into the lookup table;
3. open the output (extraction tools only);
4. loop over the haystack files;
5. print a summary.
```c
	if(argc < 4) {
		fprintf(stderr, "%s: <PORT LIST> <NEEDLE> <HAYSTACK>\n", argv[0]);
		exit(1);
	}
```
```c
	i=2;
	while(++i < argc) {
		// Search the Haystack for Needles ...
		printf("Searching %s for Port(s) %s ...\n", argv[i], argone);
		process_pcapfile(argv[i]);
	}
```

List arguments are comma-separated. Each list is split with `strtok_r`; numbers and names (`strcasecmp`) map into the table:
```c
	token = strtok_r(list, ",", &saveptr);
	while(token) {
		port = atoi(token);
		if((port > 0) && (port < 65536)) {
			g_port_a[port] = 1;
		} else {
			// EXPLICITLY MATCH PORT = 0
			if(strcasecmp(token, "ZERO") == 0) { g_port_a[0] = 1; }
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
```

## Errors

**In the tools**, a fatal error is reported on stderr, usually ending in `failed!`, and followed by `exit(1)`:
```c
	g_ph = mypcap_open(filename, lt, flags);
	if(!g_ph) { fprintf(stderr, "pcap_open(%s) failed!\n", filename); exit(1); }
```

**In library-style code** (`mypcap.c`, `process_pcapfile()`), functions return an error value instead of exiting. `mypcap_open()` returns NULL. `process_pcapfile()`, `mypcap_get_linktype()` and `mypcap_is_nsts()` return negative codes:

| Code | Meaning |
|---|---|
| -1 | open failed |
| -2 | short read / truncated |
| -3 | unsupported format |
```c
	file = fopen(filename, "r");
	if(!file) {
		fprintf(stderr, "fopen(%s, r) failed!\n", filename);
		return -1;
	}
```

## Comments

- **`// ` with a space:** short prose: `// Read File Header`.
- **`//` with no space:** parked code: `//buf += SIZE_UDP; len -= SIZE_UDP;`.
- **`/* */`:**
  - license blocks;
  - multi-line notes;
  - trailing notes on struct members;
  - references — quote the source and give its URL:
    ```c
    /*
    	https://en.wikipedia.org/wiki/EtherType
    	In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment, a unifying standard,
    	IEEE 802.3x-1997, was introduced that required that EtherType values be greater than or equal to 1536 (0x0600).
    */
    ```
- **Borrowed definitions** are credited, e.g. "Shamelessly ripped from the libpcap source code".

## Build

- Each tool directory has a bash `compile.sh` (`set -e`) that calls `gcc` directly. There is no make.
- Flags: `-Wall -pedantic -Wno-unused-but-set-variable`.
- Each tool is built three ways:

  | Build | Flags | Output |
  |---|---|---|
  | optimized | `-O2` | `.exe`, stripped |
  | debug | `-ggdb3 -DDEBUG` | `.dbg` |
  | static | `-static` | `.static.exe` |
- A new tool adds one more block that follows the existing pattern:
  ```sh
  SC="-DEXTRACT_TCP extract_l4_port.c ${EXCODE}"
  gcc         ${OPTCFLAGS} ${SC} -o pex_tcp_port.exe
  gcc         ${DBGCFLAGS} ${SC} -o pex_tcp_port.dbg
  gcc -static ${OPTCFLAGS} ${SC} -o pex_tcp_port.static.exe
  ```

## Commits

- **Subject:** short, imperative, capitalized, with no trailing period, e.g. "Add TCP Flags and ICMP echo codes", "Add match inversion to packet extract code".
- **Scope:** one logical change per commit. A commit that fixes an issue says `Fixes #N` in its message (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Known exceptions in the current code

These lines differ from the style above:
- `common/mypcap.h:68-71`: the members of `struct pcap_pkt_header` are indented with spaces. The comment at `common/l1.h:5-7` is too.
- `mypcap_t* mypcap_open(...)` puts the `*` on the type (definition and prototype).
- In `common/l2.h`, 7 `#define` lines have a tab after `#define`; the other 131 in the headers have a space.
- `common/mypcap.h:63` has trailing whitespace.
- `ETHERTYPE_IPV6 (0x86dd)` in `common/l2.h` is the only hex constant written in lowercase (22 are uppercase).

When you change one of these lines, write it in the main style. Don't reformat untouched code just for style.
