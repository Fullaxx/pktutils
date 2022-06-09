#!/bin/bash

set -e

COMMONDIR="../common"
OPT="-O2"
DBG="-ggdb3 -DDEBUG"
CFLAGS="-Wall -I${COMMONDIR} -Wno-unused-but-set-variable -DEXTRACTION -DTIMING_STATS"
CFLAGS+=" -pedantic"
OPTCFLAGS="${CFLAGS} ${OPT}"
DBGCFLAGS="${CFLAGS} ${DBG}"
EXCODE="${COMMONDIR}/pcap_reader.c ${COMMONDIR}/pcap_writer.c ${COMMONDIR}/mypcap.c ${COMMONDIR}/timing_stats.c"

rm -f *.exe *.dbg

SC="-DEXTRACT_ETHBCAST extract_eth_bcast.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_eth_bcast.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_eth_bcast.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_eth_bcast.static.exe

SC="-DEXTRACT_ETHPROTO extract_eth_proto.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_eth_proto.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_eth_proto.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_eth_proto.static.exe

SC="-DEXTRACT_IPTTL extract_ip_ttl.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_ip_ttl.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_ip_ttl.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_ip_ttl.static.exe

SC="-DEXTRACT_IPPROTO extract_ip_proto.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_ip_proto.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_ip_proto.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_ip_proto.static.exe

SC="-DEXTRACT_IP4ADDR extract_ip4_addr.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_ip4_addr.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_ip4_addr.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_ip4_addr.static.exe

SC="-DEXTRACT_IP4SUBNET extract_ip4_subnet.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_ip4_subnet.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_ip4_subnet.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_ip4_subnet.static.exe

SC="-DEXTRACT_TCP extract_l4_port.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_tcp_port.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_tcp_port.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_tcp_port.static.exe

SC="-DEXTRACT_UDP extract_l4_port.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_udp_port.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_udp_port.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_udp_port.static.exe

SC="-DEXTRACT_SCTP extract_l4_port.c ${EXCODE}"
gcc         ${OPTCFLAGS} ${SC} -o pex_sctp_port.exe
gcc         ${DBGCFLAGS} ${SC} -o pex_sctp_port.dbg
gcc -static ${OPTCFLAGS} ${SC} -o pex_sctp_port.static.exe

strip *.exe
