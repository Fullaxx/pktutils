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

## Compiling
```
cd histogram; ./compile.sh
cd extraction; ./compile.sh
```
