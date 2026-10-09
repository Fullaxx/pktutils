# Extraction Utils
Copy the packets that match a filter from one or more pcaps (the haystacks) into a new pcap (the needle file).

## Building
```
cd extraction
./compile.sh
```
This builds `pex_<filter>.exe` (optimized), `pex_<filter>.dbg` (debug) and `pex_<filter>.static.exe` for every tool below.

## Common usage
```
pex_<filter>.exe [FILTER] <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
**Files:**
- `NEEDLE` is the output pcap. It is created, or overwritten, before any haystack is read.
- The haystacks are read in the order given.
- The output takes its link type and timestamp resolution (µs or ns) from the first haystack. Timestamps from other haystacks are converted to it; ns → µs truncates.

**Output messages:** each haystack prints `Searching <file> for ... ...`. At the end the tool prints:
```
<N> packets processed in <S> seconds
<N> packets extracted to <NEEDLE>
```
The first line counts every packet read, matching or not.

**Inverting the filter:** set `INVERTMATCH=1` to extract the packets that do **not** match:
```
INVERTMATCH=1 ./pex_eth_bcast.exe unicast.pcap capture.pcap
```

**Errors:**
- The first haystack must be readable: it defines the output format, so the tool exits with status 1 if its header can't be read.
- Any later haystack that can't be opened, or isn't a supported pcap, is skipped — sometimes without a message.
- A haystack that ends in the middle of a packet is processed up to that point.
- After a skip or a partial read, the tool moves on to the next file.
- The exit status is 1 for any of these:
  - a usage error;
  - an invalid IPv4 address or subnet;
  - an unreadable first haystack;
  - an output that can't be written.

  Otherwise it is 0, even if later haystacks failed.

**Cautions:**
- **Never list the needle file among the haystacks.** For example, don't run `./pex_tcp_port.exe 80 out.pcap *.pcap` in a directory that already holds `out.pcap`. The needle is truncated before it is read. If it comes later in the list, it is read back while it is being written, which can repeat until the disk is full. Write the output somewhere the glob doesn't reach.
- **Give every haystack the same link type as the first.** Matches from a file with a different link type are still written to the output, which then labels them with the wrong link type.

## Tools

### pex_eth_bcast — broadcast and multicast frames
```
pex_eth_bcast.exe <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- Works on Ethernet captures (link type 1).
- Extracts every frame whose destination MAC address has the group bit set: the broadcast address `ff:ff:ff:ff:ff:ff` **and** every multicast address, e.g.:
  - `01:00:5e:…` (IPv4 multicast);
  - `33:33:…` (IPv6 multicast);
  - `01:80:c2:…` (STP, LLDP).
- The status line says "Broadcast Packets".

### pex_eth_proto — EtherTypes
```
pex_eth_proto.exe <ETH PROTO LIST> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- Works on Ethernet captures (link type 1) and matches the frame's outermost EtherType. A VLAN-tagged frame matches `VLAN`, not the type inside the tag.
- The list is comma-separated decimal numbers (1–65535) and/or these names (any case): `LLC PUP SPRITE IP ARP REVARP AT AARP VLAN IPX IPV6 LOOPBACK`.
- `LLC` matches IEEE 802.3 frames, whose type/length field is 1500 or less.
- Numbers are decimal: IPv4 is `2048`; `0x0800` is not understood.
- Entries that aren't recognized are ignored without a warning.

Example:
```
./pex_eth_proto.exe ARP,35020 arp_lldp.pcap capture.pcap    # 35020 = 0x88CC (LLDP)
```

### pex_ip_ttl — IPv4 TTL / IPv6 hop limit
```
pex_ip_ttl.exe <IP TTL LIST> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- Matches the TTL (IPv4) or hop limit (IPv6) of the packet's first IP header.
- The list is comma-separated decimal values from 0 to 255.

Example:
```
./pex_ip_ttl.exe 1,255 ttl.pcap capture.pcap
```

### pex_ip_proto — IP protocols
```
pex_ip_proto.exe <IP PROTO LIST> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- **What is matched:**
  - IPv4: the protocol field of the first IPv4 header.
  - IPv6: the next-header value of the first IPv6 header. A Hop-by-Hop header is skipped first, so the header after it is matched; other extension headers are not skipped.
- **The list** is comma-separated decimal numbers (1–255) and/or these names (any case): `ICMP IGMP IPIP TCP EGP PUP UDP IDP TP DCCP RSVP GRE ESP AH ICMPV6 MTP BEETPH ENCAP PIM COMP SCTP UDPLITE MPLS RAW`.
- **Protocol 0:** use the name `ZERO`; a plain `0` is ignored.

Example:
```
./pex_ip_proto.exe TCP,UDP tcp_udp.pcap captures/*.pcap
```

### pex_ip4_addr — one IPv4 address
```
pex_ip4_addr.exe <IP4 ADDR> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- Matches packets whose first IPv4 header has the address as source or destination. That header may sit inside an IPv6 tunnel.
- The address is dotted-quad, e.g. `192.168.1.10`.

### pex_ip4_subnet — an IPv4 subnet
```
pex_ip4_subnet.exe <IP4 SUBNET> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- Matches packets with a source or destination address inside the subnet. Every IPv4 header in the packet is checked, including headers inside IP tunnels.
- The subnet is in CIDR notation (`10.0.0.0/8`); host bits are ignored, so `10.1.2.3/8` is the same as `10.0.0.0/8`.

Example:
```
./pex_ip4_subnet.exe 192.168.0.0/16 lan.pcap capture.pcap
```

### pex_tcp_port, pex_udp_port, pex_sctp_port — ports
```
pex_tcp_port.exe  <PORT LIST> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
pex_udp_port.exe  <PORT LIST> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
pex_sctp_port.exe <PORT LIST> <NEEDLE> <HAYSTACK> [HAYSTACK ...]
```
- Matches packets whose TCP, UDP or SCTP source or destination port is in the list.
- The list is comma-separated decimal ports (1–65535). Use `ZERO` for port 0.
- `pex_udp_port` also matches UDP-Lite.

Example:
```
./pex_tcp_port.exe 80,443 web.pcap capture1.pcap capture2.pcap
```

## Planned
See [TODO.md](TODO.md) and the [issue tracker](https://github.com/Fullaxx/pktutils/issues).
