# Packet Utils [![Actions Status](https://github.com/Fullaxx/pktutils/workflows/CI/badge.svg)](https://github.com/Fullaxx/pktutils/actions)
A collection of utilities to assist in network analysis and packet dissection

## About
This software was written with these design goals in mind:
* Do 1 thing and do it very well
* Process **LARGE** PCAP data sets very quickly
* Do not require any non-libc dependencies
* Be easy to read, learn, and modify

Some of the structs and definitions were taken verbatim from the libpcap source code. \
This was done intentionally to support the above design decisions. \
All credit goes to those authors for making such a brilliantly easy to use software package.

## Tools
Each tool does one job. Each is the same packet reader (`common/pcap_reader.c`) compiled with a different filter or counter.

**Extraction** — copy the matching packets from one or more pcaps into a new pcap ([details](extraction/README.md)):

| Tool | Extracts packets with |
|---|---|
| `pex_eth_bcast` | an Ethernet broadcast or multicast destination address |
| `pex_eth_proto` | one of the listed EtherTypes |
| `pex_ip_ttl` | one of the listed IPv4 TTL / IPv6 hop limit values |
| `pex_ip_proto` | one of the listed IP protocols |
| `pex_ip4_addr` | the given IPv4 address as source or destination |
| `pex_ip4_subnet` | a source or destination inside the given IPv4 subnet |
| `pex_tcp_port`, `pex_udp_port`, `pex_sctp_port` | one of the listed ports as source or destination |

**Histogram** — count a header field across one or more pcaps and print CSV ([details](histogram/README.md)):

| Tool | Counts |
|---|---|
| `phist_eth_proto` | EtherTypes |
| `phist_ip_proto` | IP protocols |
| `phist_tcp_port`, `phist_udp_port`, `phist_sctp_port` | source and destination ports |

## Compiling
You need `bash` and `gcc`. The `*.static.exe` builds also need the static C library; on Debian/Ubuntu, `libc6-dev` provides it.
```
(cd histogram && ./compile.sh)
(cd extraction && ./compile.sh)
```
Each tool is built three ways, in its own directory:

| File | Build |
|---|---|
| `<tool>.exe` | optimized and stripped |
| `<tool>.dbg` | debug |
| `<tool>.static.exe` | statically linked |

## Input
The tools read classic libpcap files (`.pcap`) with microsecond or nanosecond timestamps, written in the byte order of the machine that reads them.

pcapng is not supported; convert it first with `editcap -F pcap in.pcapng out.pcap`. Byte-swapped files (written on a machine with the other byte order) are not supported either.

Supported link types:

| Link type | Value | Notes |
|---|---|---|
| Ethernet | 1 | |
| PPP | 9 | Parsed only when the frame starts with the `FF 03` address/control bytes. The `pex_*` tools don't extract from these files yet |
| Raw IP | 12, 101 | |
| Linux cooked capture v1 (SLL) | 113 | IPv4 and IPv6 payloads only |
| Raw IPv4 / raw IPv6 | 228 / 229 | |

Files with any other link type are read, but no packet in them matches. That includes Linux cooked capture v2 (SLL2, 276), which newer tcpdump writes for `-i any`, as well as BSD loopback and 802.11.

## Documentation
- [extraction/README.md](extraction/README.md): usage of each `pex_*` tool
- [histogram/README.md](histogram/README.md): usage and output of the `phist_*` tools
- [CONTRIBUTING.md](CONTRIBUTING.md): how to file an issue and send a change
- [CODING_STYLE.md](CODING_STYLE.md): the code's style and patterns
- [TODO.md](TODO.md): planned work; bugs and requests are tracked in [GitHub issues](https://github.com/Fullaxx/pktutils/issues)

## License
GNU General Public License, version 2. See [LICENSE](LICENSE).
