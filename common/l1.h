#ifndef __PKT_UTILS_LAYER_ONE__
#define __PKT_UTILS_LAYER_ONE__

/*
  Shamelessly ripped from the libpcap source code
  Thanks for making a great software package easy to read
  More info: https://www.tcpdump.org/linktypes.html
*/

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_PPP
#define DLT_PPP 9
#endif

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

/*
 * Values between 100 and 103 are used in capture file headers as
 * link-layer header type LINKTYPE_ values corresponding to DLT_ types
 * that differ between platforms; don't use those values for new DLT_
 * new types.
 */

#ifndef LINKTYPE_RAW
#define LINKTYPE_RAW 101
#endif

/* IEEE 802.11 wireless */
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif

/* Linux cooked sockets */
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

/* 802.11 plus radiotap radio header */
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO 127
#endif

/* 802.11 plus AVS radio header */
#ifndef DLT_IEEE802_11_RADIO_AVS
#define DLT_IEEE802_11_RADIO_AVS 163
#endif

#ifndef DLT_USB
#define DLT_USB 186
#endif

#ifndef DLT_USB_LINUX
#define DLT_USB_LINUX 189
#endif

#ifndef DLT_IEEE802_15_4_LINUX
#define DLT_IEEE802_15_4_LINUX 191
#endif

#ifndef DLT_USB_LINUX_MMAPPED
#define DLT_USB_LINUX_MMAPPED 220
#endif

#ifndef DLT_IPV4
#define DLT_IPV4 228
#endif

#ifndef DLT_IPV6
#define DLT_IPV6 229
#endif

#ifndef DLT_IEEE802_15_4_NOFCS
#define DLT_IEEE802_15_4_NOFCS 230
#endif

#ifndef DLT_USBPCAP
#define DLT_USBPCAP 249
#endif

/* Linux cooked sockets v2 */
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#ifndef DLT_USB_DARWIN
#define DLT_USB_DARWIN 266
#endif

#ifndef DLT_USB_2_0
#define DLT_USB_2_0 288
#endif

#endif /* __PKT_UTILS_LAYER_ONE__ */
