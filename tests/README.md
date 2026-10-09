# Tests

## mkpcap.py — sample pcaps for tests and bug reports
`mkpcap.py` builds small classic pcap files, each showing one behavior of the pktutils tools. A bug report can name a scenario instead of attaching a capture, and the tests planned for this directory will use the same files.

- **Dependencies:** Python 3 and its standard library only. The tools themselves stay C and libc-only.
- **Deterministic:** every run writes byte-identical files.
- **Addresses:** the documentation ranges (`00:00:5e:00:53:xx`, `192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`). The exception is the `ip4_tunnel` scenario, which uses private addresses for the subnet tools.
- **Checksums:** IPv4 header checksums are correct. TCP and UDP checksums are left 0, because the tools never check them. Wireshark flags a zero UDP checksum over IPv6.
- **Not committed:** generated files stay out of git (`.gitignore` ignores `*.pcap` and `*.pcapng`).

### Usage
```
python3 tests/mkpcap.py list               # list the scenarios
python3 tests/mkpcap.py eth_vlan /tmp/pk   # write one scenario into /tmp/pk
python3 tests/mkpcap.py all /tmp/pk        # write every scenario into /tmp/pk
```
It prints the path of every file it writes. Without a directory, files go into the current directory.

### Example: reproduce a problem
```
python3 tests/mkpcap.py eth_vlan /tmp/pk
extraction/pex_tcp_port.exe 80 /tmp/pk/out.pcap /tmp/pk/eth_vlan.pcap
```
`eth_vlan.pcap` holds three frames with TCP destination port 80: one untagged, one 802.1Q-tagged and one 802.1Q PPPoE frame. Today the extraction finds only the untagged one (#4).

### Scenarios
| Scenario | Files | Link type | Contents | Issues |
|---|---|---|---|---|
| `basic` | basic.pcap | 1 | TCP 51514→443; mDNS UDP 5353↔5353 to a multicast MAC; ARP request to broadcast | — |
| `edges` | edges.pcap | 1 | TCP 65535→80; UDP 5353↔5353; UDP 65535↔65535; EtherType 0xFFFF | #1, #14 |
| `big` | big.pcap | 1 | 100 full-size (1514-byte) TCP→80 frames | #2 |
| `ipv4_frag` | ipv4_frag.pcap | 1 | IPv4 first fragment TCP→80; non-first fragments whose data starts `00 50 00 50` (TCP) and `00 35 00 35` (UDP) | #3 |
| `eth_vlan` | eth_vlan.pcap | 1 | untagged TCP→80; 802.1Q TCP→80; 802.1ad + 802.1Q UDP→53; 802.1Q IPv6 TCP→443; 802.1Q PPPoE TCP→80 | #4 |
| `vlan_bomb` | vlan_bomb.pcap | 1 | one 262,144-byte frame: 65,500 stacked 802.1Q tags, then IPv4/TCP→80 | #4, #20 |
| `ipv6_ext` | ipv6_ext.pcap | 1 | 16-byte Hop-by-Hop/TCP→80; DestOpts/UDP→53; Routing/TCP→80; first fragment UDP→53; fragment at offset 800 with data `00 35 00 35`; Hop-by-Hop/DestOpts/ESP; hop limit 7 with a truncated Hop-by-Hop header | #5 |
| `sll` | sll.pcap | 113 | Linux cooked v1: IPv4, 802.1Q + IPv4, PPPoE and IPv6, each TCP→80 | #6 |
| `sll2` | sll2.pcap | 276 | Linux cooked v2: IPv4 TCP→80; IPv6 UDP→53; 802.1Q + IPv4 TCP→80 | #6 |
| `ppp` | ppp.pcap | 9 | PPP IPv4/TCP→80 with `FF 03`, without `FF 03`, and with a 1-byte protocol (PFC); an LCP request | #7 |
| `headers` | headers_empty.pcap, headers_short.pcap, headers_pcapng.pcapng, headers_swapped.pcap, headers_modified.pcap, headers_dir.pcap/ | — | inputs to reject: an empty file, 10 bytes, pcapng, a byte-swapped pcap, a modified pcap (magic 0xA1B2CD34), and a directory named like a pcap | #8, #12 |
| `lt_mix` | lt_mix_1_eth.pcap, lt_mix_2_sll.pcap | 1, 113 | the same kind of TCP→80 packet in an Ethernet file and in a Linux cooked v1 file | #9 |
| `len_clamp` | len_clamp.pcap | 1 | IPv4 total length 20 padded to 60 bytes; TSO (total length 0) TCP→80; IPv6 payload length 0 TCP→80; TCP→80 with a 4-byte FCS; TCP→80 cut by snaplen (54 of 1514 bytes) | #10, #15 |
| `badts` | badts_us.pcap, badts_ns.pcap | 1 | TCP→80 with timestamp fractions 999999 / 1000000 / 2500000 (µs file) and 999999999 / 1000000000 / 2500000000 (ns file) | #11 |
| `pppoe` | pppoe.pcap | 1 | PPPoE session IPv4/TCP→80 cut by snaplen to 100 bytes | #13 |
| `ip4_tunnel` | ip4_tunnel.pcap | 1 | IPv4-in-IPv4: outer 172.16.0.1→172.16.0.2, inner 10.1.1.1→10.2.2.2 TCP→80 | #17 |
| `dlt_null` | dlt_null.pcap | 0 | BSD loopback IPv4/TCP→80 | #21 |
| `nest` | nest.pcap | 1 | one frame with 13,105 nested IPv4-in-IPv4 headers around TCP→80 | #20 |
| `l4_trunc` | l4_trunc.pcap | 1 | TCP→80 cut by snaplen 6 bytes into the TCP header; an RFC 1858 tiny first fragment with 8 bytes of TCP | #22 |

### Using it from Python
The builders can also be imported:
```python
import sys
sys.path.insert(0, "tests")
import mkpcap

pkt = mkpcap.eth(0x0800, mkpcap.ipv4(6, mkpcap.tcp(1234, 80)))
mkpcap.write_pcap("one.pcap", mkpcap.LT_EN10MB, mkpcap.records([pkt]))
```
What's available:

| Group | Functions |
|---|---|
| Link layer | `eth`, `vlan`, `sll`, `sll2`, `ppp`, `pppoe`, `arp_request`, `lcp_configure_request` |
| IP layer | `ipv4`, `ipv4_header`, `ipv6`, `ipv6_ext`, `ipv6_srh`, `ipv6_frag` |
| Transport | `tcp`, `udp`, `sctp`, `esp` |
| Files | `record`, `records`, `pcap_bytes`, `write_pcap`, `pcapng_bytes`, `modified_pcap_bytes` |

### Adding a scenario
1. Write a function that returns `[(file name, bytes)]`. A `None` in place of the bytes creates a directory.
2. Register it with `@scenario(name, files, linktypes, issues, description)`.
3. Keep it deterministic — no clocks, no randomness — and use the documentation addresses.
4. Add a row to the table above.
