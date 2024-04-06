# TCP_Parser

C++ Parser for TCP pcap file

## Env. info
OS: Ubuntu 22.04, WSL

Library: PcapPlusPlus

sample pcap file:

  - sample1.pcap: `chargen-tcp.pcap` (libpcap) Chargen over TCP.
  
  - sample2.pcap: `cmp_in_http_with_pkixcmp-poll_content_type.pcap` (libpcap) Certificate Management Protocol (CMP) version 2 encapsulated in HTTP. The CMP messages are of the deprecated but used content-type "pkixcmp-poll", so they are using the TCP transport style. In two of the four CMP messages, the content type is not explicitly set, thus they cannot be dissected correctly.

from Wireshark SampleCaptures (https://wiki.wireshark.org/SampleCaptures)

## How to run
1. Clone this repository
2. Change pcap file name to `sample.pcap`
3. run `build_n_run`
