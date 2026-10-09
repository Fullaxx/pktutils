#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Part of pktutils. GNU General Public License, version 2 (see LICENSE).
"""mkpcap.py - make small pcap files for tests and bug reports

usage: mkpcap.py list               list the scenarios
       mkpcap.py <scenario> [DIR]   write one scenario's file(s) into DIR (default .)
       mkpcap.py all [DIR]          write every scenario

Each scenario writes classic pcap files that show one behavior of the
pktutils tools. Only the Python standard library is used, and every run
writes byte-identical files. IPv4 header checksums are correct; TCP and
UDP checksums are left 0 (the tools never check them). See tests/README.md.
"""

import os
import socket
import struct
import sys

# Link types (the pcap file header value)
LT_NULL = 0
LT_EN10MB = 1
LT_PPP = 9
LT_LINUX_SLL = 113
LT_LINUX_SLL2 = 276

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAP_MAGIC_MODIFIED = 0xA1B2CD34
MAXPKT = 262144                 # largest packet the tools read

NATIVE = "<" if sys.byteorder == "little" else ">"
SWAPPED = ">" if NATIVE == "<" else "<"

BASE_SEC = 1700000000           # 2023-11-14 22:13:20 UTC; packet i is at BASE_SEC + i

# Documentation addresses (RFC 7042, RFC 5737, RFC 3849)
MAC_A = "00:00:5e:00:53:01"
MAC_B = "00:00:5e:00:53:02"
IP4_A = "192.0.2.1"
IP4_B = "198.51.100.2"
IP6_A = "2001:db8::1"
IP6_B = "2001:db8::2"


# ---------------------------------------------------------------- pcap files

def record(data, sec=BASE_SEC, frac=0, orig=None):
    """One pcap record: (packet bytes, seconds, fraction, original length)."""
    return (data, sec, frac, len(data) if orig is None else orig)


def records(packets):
    """One record per packet, one second apart."""
    return [record(p, BASE_SEC + i) for i, p in enumerate(packets)]


def pcap_bytes(linktype, recs, ns=False, magic=None, order=NATIVE):
    """A classic pcap file (version 2.4). Fractions are us, or ns if ns=True."""
    if magic is None:
        magic = PCAP_MAGIC_NS if ns else PCAP_MAGIC_US
    out = [struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, MAXPKT, linktype)]
    for data, sec, frac, orig in recs:
        out.append(struct.pack(order + "IIII", sec, frac, len(data), orig))
        out.append(data)
    return b"".join(out)


def write_pcap(path, linktype, recs, ns=False, magic=None, order=NATIVE):
    with open(path, "wb") as f:
        f.write(pcap_bytes(linktype, recs, ns=ns, magic=magic, order=order))
    return path


def pcapng_bytes(linktype, packets):
    """A minimal pcapng file: section header, one interface, one block per packet."""
    def block(btype, body):
        body += b"\0" * (-len(body) % 4)
        total = 12 + len(body)
        return struct.pack(NATIVE + "II", btype, total) + body + struct.pack(NATIVE + "I", total)

    out = [block(0x0A0D0D0A, struct.pack(NATIVE + "IHHq", 0x1A2B3C4D, 1, 0, -1)),
           block(0x00000001, struct.pack(NATIVE + "HHI", linktype, 0, MAXPKT))]
    for i, data in enumerate(packets):
        ts = (BASE_SEC + i) * 1000000          # default resolution: microseconds
        out.append(block(0x00000006, struct.pack(NATIVE + "IIIII", 0, ts >> 32, ts & 0xFFFFFFFF,
                                                 len(data), len(data)) + data))
    return b"".join(out)


def modified_pcap_bytes(linktype, packets):
    """Modified pcap (magic 0xA1B2CD34): 24-byte record headers that add ifindex/protocol/type."""
    out = [struct.pack(NATIVE + "IHHiIII", PCAP_MAGIC_MODIFIED, 2, 4, 0, 0, MAXPKT, linktype)]
    for i, data in enumerate(packets):
        out.append(struct.pack(NATIVE + "IIIIiHBB", BASE_SEC + i, 0, len(data), len(data),
                               1, 0x0800, 0, 0))
        out.append(data)
    return b"".join(out)


# ---------------------------------------------------------------- link layer

def mac(text):
    return bytes(int(x, 16) for x in text.split(":"))


def eth(etype, payload, dst=MAC_B, src=MAC_A):
    return mac(dst) + mac(src) + struct.pack(">H", etype) + payload


def vlan(etype, payload, vid=10, pcp=0):
    """What follows a VLAN TPID (0x8100, 0x88A8): the TCI, the next EtherType, the payload."""
    return struct.pack(">HH", (pcp << 13) | vid, etype) + payload


def sll(proto, payload, pkttype=0, hatype=1, addr=MAC_A):
    """Linux cooked capture v1 header (16 bytes)."""
    a = mac(addr)
    return struct.pack(">HHH8sH", pkttype, hatype, len(a), a, proto) + payload


def sll2(proto, payload, ifindex=1, hatype=1, pkttype=0, addr=MAC_A):
    """Linux cooked capture v2 header (20 bytes)."""
    a = mac(addr)
    return struct.pack(">HHIHBB8s", proto, 0, ifindex, hatype, pkttype, len(a), a) + payload


def ppp(proto, payload, framing=True, pfc=False):
    """PPP: optional FF 03 address/control, then a 2-byte (or, with PFC, 1-byte) protocol."""
    head = b"\xff\x03" if framing else b""
    if pfc:
        assert proto < 0x100 and proto & 1, "PFC needs an odd one-byte protocol"
        head += struct.pack(">B", proto)
    else:
        head += struct.pack(">H", proto)
    return head + payload


def pppoe(proto, payload, session=0x1234):
    """PPPoE session header, PPP protocol, payload. The length field covers protocol + payload."""
    body = struct.pack(">H", proto) + payload
    return struct.pack(">BBHH", 0x11, 0x00, session, len(body)) + body


def arp_request(sha=MAC_A, spa=IP4_A, tpa=IP4_B):
    return struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1,
                       mac(sha), ip4(spa), b"\0" * 6, ip4(tpa))


def lcp_configure_request(magic=0x12345678):
    opts = struct.pack(">BBH", 1, 4, 1500) + struct.pack(">BBI", 5, 6, magic)
    return struct.pack(">BBH", 1, 1, 4 + len(opts)) + opts


# ---------------------------------------------------------------- IP layer

def ip4(text):
    return socket.inet_pton(socket.AF_INET, text)


def ip6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4_header(proto, tot_len, src=IP4_A, dst=IP4_B, ttl=64, ident=1, frag=0, mf=False, df=False):
    """A 20-byte IPv4 header. frag is the fragment offset in 8-byte units."""
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | frag
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot_len, ident, flags, ttl, proto, 0,
                      ip4(src), ip4(dst))
    return hdr[:10] + struct.pack(">H", checksum(hdr)) + hdr[12:]


def ipv4(proto, payload, tot_len=None, **kw):
    """IPv4 header + payload. tot_len defaults to the real length (capped at 65535)."""
    if tot_len is None:
        tot_len = min(20 + len(payload), 0xFFFF)
    return ipv4_header(proto, tot_len, **kw) + payload


def ipv6(nh, payload, src=IP6_A, dst=IP6_B, hlim=64, plen=None):
    if plen is None:
        plen = len(payload)
    return struct.pack(">IHBB16s16s", 6 << 28, plen, nh, hlim, ip6(src), ip6(dst)) + payload


def ipv6_ext(nh, payload, n=0):
    """Hop-by-Hop or Destination Options header: (n+1)*8 bytes, padded with one PadN option."""
    size = (n + 1) * 8
    return struct.pack(">BBBB", nh, n, 1, size - 4) + b"\0" * (size - 4) + payload


def ipv6_srh(nh, payload, segment=IP6_B):
    """Routing header type 4 (segment routing) with one segment: 24 bytes, Hdr Ext Len 2."""
    return struct.pack(">BBBBBBH16s", nh, 2, 4, 0, 0, 0, 0, ip6(segment)) + payload


def ipv6_frag(nh, payload, offset=0, more=False, ident=0x12345678):
    """Fragment header (8 bytes). offset is in 8-byte units."""
    return struct.pack(">BBHI", nh, 0, (offset << 3) | (1 if more else 0), ident) + payload


# ---------------------------------------------------------------- transport

def tcp(sport, dport, payload=b"", flags=0x02, seq=1):
    """A 20-byte TCP header (SYN by default) + payload. The checksum is left 0."""
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def sctp(sport, dport, payload=b"", vtag=0):
    return struct.pack(">HHII", sport, dport, vtag, 0) + payload


def esp(spi=0x100, seq=1, payload=b"\0" * 16):
    return struct.pack(">II", spi, seq) + payload


# ---------------------------------------------------------------- scenarios

SCENARIOS = {}


def scenario(name, files, linktypes, issues, desc):
    """Register a scenario. Its function returns [(file name, bytes)]; None bytes = a directory."""
    def register(fn):
        SCENARIOS[name] = {"build": fn, "files": files, "linktypes": linktypes,
                           "issues": issues, "desc": desc}
        return fn
    return register


def tcp80(sport, payload=b""):
    """The usual test packet: Ethernet / IPv4 / TCP sport -> 80."""
    return eth(0x0800, ipv4(6, tcp(sport, 80, payload)))


@scenario("basic", ["basic.pcap"], [LT_EN10MB], [],
          "TCP 51514->443, mDNS UDP 5353<->5353 to a multicast MAC, ARP request to broadcast")
def s_basic():
    return [("basic.pcap", pcap_bytes(LT_EN10MB, records([
        eth(0x0800, ipv4(6, tcp(51514, 443))),
        eth(0x0800, ipv4(17, udp(5353, 5353, b"\0" * 12), dst="224.0.0.251", ttl=255),
            dst="01:00:5e:00:00:fb"),
        eth(0x0806, arp_request(), dst="ff:ff:ff:ff:ff:ff"),
    ])))]


@scenario("edges", ["edges.pcap"], [LT_EN10MB], [1, 14],
          "TCP 65535->80, UDP 5353<->5353, UDP 65535<->65535, EtherType 0xFFFF")
def s_edges():
    return [("edges.pcap", pcap_bytes(LT_EN10MB, records([
        eth(0x0800, ipv4(6, tcp(65535, 80))),
        eth(0x0800, ipv4(17, udp(5353, 5353, b"\0" * 12))),
        eth(0x0800, ipv4(17, udp(65535, 65535, b"\0" * 12))),
        eth(0xFFFF, b"\0" * 46),
    ])))]


@scenario("big", ["big.pcap"], [LT_EN10MB], [2],
          "100 full-size (1514-byte) TCP->80 frames, about 150 KB")
def s_big():
    return [("big.pcap", pcap_bytes(LT_EN10MB, records(
        [tcp80(40000 + i, b"\0" * 1460) for i in range(100)])))]


@scenario("ipv4_frag", ["ipv4_frag.pcap"], [LT_EN10MB], [3],
          "IPv4 first fragment TCP->80; non-first fragments whose data starts "
          "00 50 00 50 (TCP) and 00 35 00 35 (UDP)")
def s_ipv4_frag():
    return [("ipv4_frag.pcap", pcap_bytes(LT_EN10MB, records([
        eth(0x0800, ipv4(6, tcp(40001, 80, b"\0" * 1460), ident=0x1111, mf=True)),
        eth(0x0800, ipv4(6, b"\x00\x50\x00\x50" + b"\0" * 16, ident=0x1111, frag=185)),
        eth(0x0800, ipv4(17, b"\x00\x35\x00\x35" + b"\0" * 4, ident=0x2222, frag=185)),
    ])))]


@scenario("eth_vlan", ["eth_vlan.pcap"], [LT_EN10MB], [4],
          "untagged TCP->80; 802.1Q TCP->80; 802.1ad+802.1Q UDP->53; "
          "802.1Q IPv6 TCP->443; 802.1Q PPPoE TCP->80")
def s_eth_vlan():
    return [("eth_vlan.pcap", pcap_bytes(LT_EN10MB, records([
        eth(0x0800, ipv4(6, tcp(40001, 80))),
        eth(0x8100, vlan(0x0800, ipv4(6, tcp(40002, 80)))),
        eth(0x88A8, vlan(0x8100, vlan(0x0800, ipv4(17, udp(40003, 53, b"\0" * 12)), vid=20),
                         vid=100)),
        eth(0x8100, vlan(0x86DD, ipv6(6, tcp(40004, 443)))),
        eth(0x8100, vlan(0x8864, pppoe(0x0021, ipv4(6, tcp(40005, 80))))),
    ])))]


@scenario("vlan_bomb", ["vlan_bomb.pcap"], [LT_EN10MB], [4, 20],
          "one 262,144-byte frame: 65,500 stacked 802.1Q tags, then IPv4/TCP->80")
def s_vlan_bomb():
    tags = 65500
    pad = MAXPKT - (14 + 4 * tags + 40)
    stack = struct.pack(">HH", 10, 0x8100) * (tags - 1) + struct.pack(">HH", 10, 0x0800)
    frame = eth(0x8100, stack + ipv4(6, tcp(40006, 80, b"\0" * pad)))
    assert len(frame) == MAXPKT
    return [("vlan_bomb.pcap", pcap_bytes(LT_EN10MB, records([frame])))]


@scenario("ipv6_ext", ["ipv6_ext.pcap"], [LT_EN10MB], [5],
          "IPv6: 16-byte Hop-by-Hop/TCP->80; DestOpts/UDP->53; Routing/TCP->80; "
          "first fragment UDP->53; fragment at offset 800 with data 00 35 00 35; "
          "HBH/DestOpts/ESP; hop limit 7 with a truncated Hop-by-Hop")
def s_ipv6_ext():
    cut = eth(0x86DD, ipv6(0, ipv6_ext(59, b""), hlim=7))
    pkts = records([
        eth(0x86DD, ipv6(0, ipv6_ext(6, tcp(40010, 80), n=1))),
        eth(0x86DD, ipv6(60, ipv6_ext(17, udp(40011, 53, b"\0" * 12)))),
        eth(0x86DD, ipv6(43, ipv6_srh(6, tcp(40012, 80)))),
        eth(0x86DD, ipv6(44, ipv6_frag(17, udp(40013, 53, b"\0" * 24), more=True, ident=0x1111))),
        eth(0x86DD, ipv6(44, ipv6_frag(17, b"\x00\x35\x00\x35" + b"\0" * 4,
                                       offset=100, ident=0x2222))),
        eth(0x86DD, ipv6(0, ipv6_ext(60, ipv6_ext(50, esp())))),
    ])
    # snaplen keeps 1 byte of the Hop-by-Hop header
    pkts.append(record(cut[:55], BASE_SEC + len(pkts), orig=len(cut)))
    return [("ipv6_ext.pcap", pcap_bytes(LT_EN10MB, pkts))]


@scenario("sll", ["sll.pcap"], [LT_LINUX_SLL], [6],
          "Linux cooked v1: IPv4, 802.1Q+IPv4, PPPoE and IPv6, each TCP->80")
def s_sll():
    return [("sll.pcap", pcap_bytes(LT_LINUX_SLL, records([
        sll(0x0800, ipv4(6, tcp(40020, 80))),
        sll(0x8100, vlan(0x0800, ipv4(6, tcp(40021, 80)))),
        sll(0x8864, pppoe(0x0021, ipv4(6, tcp(40022, 80)))),
        sll(0x86DD, ipv6(6, tcp(40023, 80))),
    ])))]


@scenario("sll2", ["sll2.pcap"], [LT_LINUX_SLL2], [6],
          "Linux cooked v2: IPv4 TCP->80, IPv6 UDP->53, 802.1Q+IPv4 TCP->80")
def s_sll2():
    return [("sll2.pcap", pcap_bytes(LT_LINUX_SLL2, records([
        sll2(0x0800, ipv4(6, tcp(40030, 80))),
        sll2(0x86DD, ipv6(17, udp(40031, 53, b"\0" * 12))),
        sll2(0x8100, vlan(0x0800, ipv4(6, tcp(40032, 80)))),
    ])))]


@scenario("ppp", ["ppp.pcap"], [LT_PPP], [7],
          "PPP IPv4/TCP->80 with FF 03, without FF 03, and with a 1-byte protocol (PFC); "
          "an LCP request")
def s_ppp():
    return [("ppp.pcap", pcap_bytes(LT_PPP, records([
        ppp(0x0021, ipv4(6, tcp(40040, 80))),
        ppp(0x0021, ipv4(6, tcp(40041, 80)), framing=False),
        ppp(0x21, ipv4(6, tcp(40042, 80)), framing=False, pfc=True),
        ppp(0xC021, lcp_configure_request()),
    ])))]


@scenario("headers", ["headers_empty.pcap", "headers_short.pcap", "headers_pcapng.pcapng",
                      "headers_swapped.pcap", "headers_modified.pcap", "headers_dir.pcap/"],
          [], [8, 12],
          "inputs to reject: empty, 10 bytes, pcapng, byte-swapped pcap, "
          "modified pcap (0xA1B2CD34), a directory named like a pcap")
def s_headers():
    pkt = tcp80(40050)
    return [
        ("headers_empty.pcap", b""),
        ("headers_short.pcap", pcap_bytes(LT_EN10MB, records([pkt]))[:10]),
        ("headers_pcapng.pcapng", pcapng_bytes(LT_EN10MB, [pkt])),
        ("headers_swapped.pcap", pcap_bytes(LT_EN10MB, records([pkt]), order=SWAPPED)),
        ("headers_modified.pcap", modified_pcap_bytes(LT_EN10MB, [pkt])),
        ("headers_dir.pcap", None),
    ]


@scenario("lt_mix", ["lt_mix_1_eth.pcap", "lt_mix_2_sll.pcap"], [LT_EN10MB, LT_LINUX_SLL], [9],
          "TCP->80 in an Ethernet file and in a Linux cooked v1 file")
def s_lt_mix():
    return [
        ("lt_mix_1_eth.pcap", pcap_bytes(LT_EN10MB, records([tcp80(40051)]))),
        ("lt_mix_2_sll.pcap",
         pcap_bytes(LT_LINUX_SLL, records([sll(0x0800, ipv4(6, tcp(40052, 80)))]))),
    ]


@scenario("len_clamp", ["len_clamp.pcap"], [LT_EN10MB], [10, 15],
          "IPv4 total length 20 padded to 60 bytes; TSO (total length 0) TCP->80; "
          "IPv6 payload length 0 TCP->80; TCP->80 + 4-byte FCS; "
          "TCP->80 cut by snaplen (54 of 1514 bytes)")
def s_len_clamp():
    full = tcp80(40064, b"\0" * 1460)
    pkts = records([
        eth(0x0800, ipv4(6, b"", tot_len=20) + b"\0" * 26),
        eth(0x0800, ipv4(6, tcp(40061, 80, b"\0" * 100), tot_len=0)),
        eth(0x86DD, ipv6(6, tcp(40062, 80), plen=0)),
        tcp80(40063) + b"\xde\xad\xbe\xef",
    ])
    pkts.append(record(full[:54], BASE_SEC + len(pkts), orig=len(full)))
    return [("len_clamp.pcap", pcap_bytes(LT_EN10MB, pkts))]


@scenario("badts", ["badts_us.pcap", "badts_ns.pcap"], [LT_EN10MB], [11],
          "TCP->80 with timestamp fractions 999999 / 1000000 / 2500000 (us) "
          "and 999999999 / 1e9 / 2.5e9 (ns)")
def s_badts():
    us_fracs = [999999, 1000000, 2500000]
    ns_fracs = [999999999, 1000000000, 2500000000]
    us = [record(tcp80(40070 + i), BASE_SEC + i, f) for i, f in enumerate(us_fracs)]
    ns = [record(tcp80(40073 + i), BASE_SEC + i, f) for i, f in enumerate(ns_fracs)]
    return [("badts_us.pcap", pcap_bytes(LT_EN10MB, us)),
            ("badts_ns.pcap", pcap_bytes(LT_EN10MB, ns, ns=True))]


@scenario("pppoe", ["pppoe.pcap"], [LT_EN10MB], [13],
          "PPPoE session IPv4/TCP->80 cut by snaplen to 100 bytes")
def s_pppoe():
    full = eth(0x8864, pppoe(0x0021, ipv4(6, tcp(40080, 80, b"\0" * 1400))))
    return [("pppoe.pcap", pcap_bytes(LT_EN10MB, [record(full[:100], orig=len(full))]))]


@scenario("ip4_tunnel", ["ip4_tunnel.pcap"], [LT_EN10MB], [17],
          "IPv4-in-IPv4: outer 172.16.0.1->172.16.0.2, inner 10.1.1.1->10.2.2.2 TCP->80")
def s_ip4_tunnel():
    inner = ipv4(6, tcp(40090, 80), src="10.1.1.1", dst="10.2.2.2")
    return [("ip4_tunnel.pcap", pcap_bytes(LT_EN10MB, records([
        eth(0x0800, ipv4(4, inner, src="172.16.0.1", dst="172.16.0.2")),
    ])))]


@scenario("dlt_null", ["dlt_null.pcap"], [LT_NULL], [21],
          "BSD loopback (link type 0) IPv4/TCP->80")
def s_dlt_null():
    family = struct.pack(NATIVE + "I", socket.AF_INET)    # host byte order, as BSD writes it
    return [("dlt_null.pcap", pcap_bytes(LT_NULL, records([family + ipv4(6, tcp(40100, 80))])))]


@scenario("nest", ["nest.pcap"], [LT_EN10MB], [20],
          "one frame with 13,105 nested IPv4-in-IPv4 headers around TCP->80")
def s_nest():
    levels = 13105
    inner = tcp(40110, 80)
    hdrs = []
    for k in range(levels):
        rest = 20 * (levels - k - 1) + len(inner)
        hdrs.append(ipv4_header(6 if k == levels - 1 else 4, min(20 + rest, 0xFFFF)))
    frame = eth(0x0800, b"".join(hdrs) + inner)
    assert len(frame) <= MAXPKT
    return [("nest.pcap", pcap_bytes(LT_EN10MB, records([frame])))]


@scenario("l4_trunc", ["l4_trunc.pcap"], [LT_EN10MB], [22],
          "TCP->80 cut by snaplen 6 bytes into the TCP header; "
          "RFC 1858 tiny first fragment with 8 bytes of TCP")
def s_l4_trunc():
    full = tcp80(40120, b"\0" * 100)
    pkts = [record(full[:40], BASE_SEC, orig=len(full))]
    pkts.append(record(eth(0x0800, ipv4(6, tcp(40121, 80)[:8], mf=True)), BASE_SEC + 1))
    return [("l4_trunc.pcap", pcap_bytes(LT_EN10MB, pkts))]


# ---------------------------------------------------------------- command line

def list_scenarios():
    print("%-11s %-9s %-8s %s" % ("SCENARIO", "LINKTYPE", "ISSUES", "CONTENTS"))
    for name, sc in SCENARIOS.items():
        lts = ",".join(str(lt) for lt in sc["linktypes"]) or "-"
        issues = " ".join("#%d" % i for i in sc["issues"]) or "-"
        print("%-11s %-9s %-8s %s" % (name, lts, issues, sc["desc"]))
        print("%-11s %-9s %-8s files: %s" % ("", "", "", " ".join(sc["files"])))


def write_scenario(name, outdir):
    for fname, data in SCENARIOS[name]["build"]():
        path = os.path.join(outdir, fname)
        if data is None:
            os.makedirs(path, exist_ok=True)
        else:
            with open(path, "wb") as f:
                f.write(data)
        print(path)


def main(argv):
    if len(argv) < 2 or len(argv) > 3 or argv[1] in ("-h", "--help"):
        sys.stderr.write(__doc__.split("\n\n")[1] + "\n")
        return 1
    cmd = argv[1]
    if cmd == "list":
        list_scenarios()
        return 0
    names = list(SCENARIOS) if cmd == "all" else [cmd]
    for name in names:
        if name not in SCENARIOS:
            sys.stderr.write("mkpcap.py: unknown scenario '%s' (try: mkpcap.py list)\n" % name)
            return 1
    outdir = argv[2] if len(argv) == 3 else "."
    os.makedirs(outdir, exist_ok=True)
    for name in names:
        write_scenario(name, outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
