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
