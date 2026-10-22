# pcap

**English** · [中文](README.zh-CN.md)

[![CI](https://github.com/turinglambdaai/pcap/actions/workflows/ci.yml/badge.svg)](https://github.com/turinglambdaai/pcap/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A pure-Racket reader for classic pcap capture files (the libpcap/tcpdump format), with dissection of Ethernet II (including 802.1Q/802.1ad VLAN tags), IPv4, IPv6 (header only), TCP, and UDP. No FFI, no system dependencies — only `base`.

## Installation

```sh
raco pkg install pcap
```

## Example

```racket
(require pcap)

;; Read every packet from a capture file, in capture order.
(define pkts (pcap-read-file "capture.pcap"))
(define pkt (first pkts))

;; Timestamps are exact rational seconds; data holds the captured bytes.
(packet-timestamp pkt)   ; e.g. 1700000000+1/2
(packet-orig-len pkt)    ; original wire length (incl_len may be shorter: snaplen)

;; Dissect into a nested Ethernet -> IPv4 -> TCP structure.
(define eth (decode-packet pkt))
(ethernet-frame-src eth)                 ; "aa:bb:cc:dd:ee:ff"
(define ip (ethernet-frame-payload eth)) ; ipv4-header?
(ipv4-header-src ip)                     ; "192.168.1.1"
(define tcp (ipv4-header-payload ip))    ; tcp-header?
(tcp-header-dst-port tcp)                ; 443
```

## Scope

- Classic pcap only, all four magic variants (both byte orders, both timestamp resolutions):

  | Magic (octets on disk) | Byte order    | Timestamp unit |
  | ---------------------- | ------------- | -------------- |
  | `a1 b2 c3 d4`          | big-endian    | microseconds   |
  | `d4 c3 b2 a1`          | little-endian | microseconds   |
  | `a1 b2 3c 4d`          | big-endian    | nanoseconds    |
  | `4d 3c b2 a1`          | little-endian | nanoseconds    |

- **pcapng is out of scope**: feeding a pcapng file to any reader raises `exn:fail` with a "bad magic number" message.
- Per packet, the reader keeps both lengths: `packet-data` holds exactly `incl_len` captured bytes, while `packet-orig-len` preserves the original wire length when the snapshot length truncated the packet.
- Dissection covers Ethernet II (802.1Q/802.1ad VLAN tags, including QinQ), IPv4 (with options), the fixed IPv6 header (extension headers are not parsed), TCP, and UDP. Checksums are not validated.

The [reference manual](pcap/scribblings/pcap.scrbl) is part of the package; after installing, read it with `raco docs pcap`.

## License

[MIT](LICENSE)
