# pcap

**English** · [中文](README.zh-CN.md)

[![CI](https://github.com/turinglambdaai/pcap/actions/workflows/ci.yml/badge.svg)](https://github.com/turinglambdaai/pcap/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A pure-Racket reader for classic pcap capture files (the libpcap/tcpdump format), with dissection of Ethernet II (including 802.1Q/802.1ad VLAN tags), IPv4, IPv6 (header only), TCP, and UDP. No FFI, no system dependencies — only `base`.

## Installation

```sh
raco pkg install pcap
```

## Example

This self-contained example parses a **synthetic** classic pcap capture in
memory; it requires no network privileges, external capture file or hardware.

```racket
#lang racket/base
(require pcap)
;; One synthetic Ethernet packet in a classic pcap container.
(define capture
  (bytes-append
   (bytes #xa1 #xb2 #xc3 #xd4 0 2 0 4 0 0 0 0 0 0 0 0
          0 0 #xff #xff 0 0 0 1)
   (bytes 0 0 0 1 0 0 0 0 0 0 0 16 0 0 0 16)
   (bytes #xaa #xbb #xcc #xdd #xee #xff
          #x11 #x22 #x33 #x44 #x55 #x66 #x88 #xb5 #xde #xad)))
(define pkt (car (pcap-read-bytes capture)))
(packet-timestamp pkt)                    ; => 1 (exact seconds)
(ethernet-frame-src (decode-packet pkt))  ; => "11:22:33:44:55:66"
```

To read your own classic capture, use `(pcap-read-file "capture.pcap")`.
The checked-in [executable quickstart](examples/quickstart.rkt) asserts the
packet count, timestamp, original length, EtherType and decoded payload.

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

## API and development

The [Scribble API manual](pcap/scribblings/pcap.scrbl) is authoritative for
reader contracts, dissection, error behavior and unsupported pcapng. The
unit suite covers four magic variants, truncation and malformed inputs.
From the repository root (Racket installed):

```sh
raco pkg install --auto --link "$(pwd)"
raco test -p pcap
racket examples/quickstart.rkt
raco setup -l pcap --check-pkg-deps
```

CI checks these steps on Linux, macOS and Windows. For issues, include a
synthetic, non-sensitive reproducer and your Racket version at
[GitHub Issues](https://github.com/turinglambdaai/pcap/issues).

## License

[MIT](LICENSE)
