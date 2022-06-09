#!/bin/bash

set -e

COMMONDIR="../common"
OPT="-O2"
DBG="-ggdb3 -DDEBUG"
CFLAGS="-Wall -I${COMMONDIR} -Wno-unused-but-set-variable"
CFLAGS+=" -pedantic"
OPTCFLAGS="${CFLAGS} ${OPT}"
DBGCFLAGS="${CFLAGS} ${DBG}"

rm -f *.exe *.dbg

SC="-DHIST_ETHPROTO histmain.c ${COMMONDIR}/pcap_reader.c"
gcc         ${OPTCFLAGS} ${SC} -o phist_eth_proto.exe
gcc         ${DBGCFLAGS} ${SC} -o phist_eth_proto.dbg
gcc -static ${OPTCFLAGS} ${SC} -o phist_eth_proto.static.exe

SC="-DHIST_IPPROTO histmain.c ${COMMONDIR}/pcap_reader.c"
gcc         ${OPTCFLAGS} ${SC} -o phist_ip_proto.exe
gcc         ${DBGCFLAGS} ${SC} -o phist_ip_proto.dbg
gcc -static ${OPTCFLAGS} ${SC} -o phist_ip_proto.static.exe

SC="-DHIST_TCPPORT histmain.c ${COMMONDIR}/pcap_reader.c"
gcc         ${OPTCFLAGS} ${SC} -o phist_tcp_port.exe
gcc         ${DBGCFLAGS} ${SC} -o phist_tcp_port.dbg
gcc -static ${OPTCFLAGS} ${SC} -o phist_tcp_port.static.exe

SC="-DHIST_UDPPORT histmain.c ${COMMONDIR}/pcap_reader.c"
gcc         ${OPTCFLAGS} ${SC} -o phist_udp_port.exe
gcc         ${DBGCFLAGS} ${SC} -o phist_udp_port.dbg
gcc -static ${OPTCFLAGS} ${SC} -o phist_udp_port.static.exe

SC="-DHIST_SCTPPORT histmain.c ${COMMONDIR}/pcap_reader.c"
gcc         ${OPTCFLAGS} ${SC} -o phist_sctp_port.exe
gcc         ${DBGCFLAGS} ${SC} -o phist_sctp_port.dbg
gcc -static ${OPTCFLAGS} ${SC} -o phist_sctp_port.static.exe

strip *.exe
