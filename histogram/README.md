# Histogram Utils
A collection of utilities to assist in network analysis and packet dissection

## Howto
These tools will create a histogram of various parts of network packets. \
The output will be text in CSV format. View them as text or as a spreadsheet.
```
cd histogram
./compile.sh
./phist_eth_proto.exe *.pcap >eth_proto.csv
./phist_ip_proto.exe  *.pcap >ip_proto.csv
./phist_sctp_port.exe *.pcap >sctp_port.csv
./phist_tcp_port.exe  *.pcap >tcp_port.csv
./phist_udp_port.exe  *.pcap >udp_port.csv
```
`compile.sh` builds `phist_<field>.exe` (optimized), `phist_<field>.dbg` (debug) and `phist_<field>.static.exe` for each tool.

## Output
Every tool reads all the pcaps named on the command line and prints one table to stdout:
- a header line;
- one row per value seen, in ascending order of value. Values that were never seen are left out;
- EtherTypes are printed in hex (`0x0800`); everything else in decimal.
```
TCP PORT,COUNT,%
443,1000,100.00%
51514,600,60.00%
51515,400,40.00%
```
COUNT is how many times the value was seen. % is COUNT divided by the tool's total, which differs per tool:

| Tool | Header | What is counted | % is relative to |
|---|---|---|---|
| `phist_eth_proto` | `ETH PROTO,COUNT,%` | The outermost EtherType of each Ethernet II frame (type/length field above 1500). IEEE 802.3/LLC frames are not counted. Ethernet captures only (link type 1) | Number of Ethernet II frames |
| `phist_ip_proto` | `IP PROTO,COUNT,%` | IPv4: the protocol of each IPv4 header. IPv6: the next header of each IPv6 header, after skipping a Hop-by-Hop header. Each IP header of a tunnel counts | Number of IP headers counted |
| `phist_tcp_port` | `TCP PORT,COUNT,%` | Each packet adds 1 to its source port and 1 to its destination port | Number of TCP packets |
| `phist_udp_port` | `UDP PORT,COUNT,%` | The same, for UDP; UDP-Lite is included | Number of UDP packets |
| `phist_sctp_port` | `SCTP PORT,COUNT,%` | The same, for SCTP | Number of SCTP packets |

Because the port tools count two ports per packet, their % column adds up to about 200%. A port's % is roughly the share of packets that use it. A packet whose source and destination ports are equal counts twice for that port ([#14](https://github.com/Fullaxx/pktutils/issues/14)).

The link types the tools can read are listed in the [main README](../README.md#input). How files are handled:
- A file that can't be opened, or isn't a supported pcap, is skipped — sometimes without a message.
- A file that ends in the middle of a packet is counted up to that point.
- The exit status is 0 either way ([#12](https://github.com/Fullaxx/pktutils/issues/12)).

## Known issues
Port 65535 and EtherType 0xFFFF are not reported. Counting them writes one element past the end of the counter array ([#1](https://github.com/Fullaxx/pktutils/issues/1)).

Other open problems are tracked as [bug issues](https://github.com/Fullaxx/pktutils/issues?q=is%3Aissue+is%3Aopen+label%3Abug).
