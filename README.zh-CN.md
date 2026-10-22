# pcap

[English](README.md) · **中文**

[![CI](https://github.com/turinglambdaai/pcap/actions/workflows/ci.yml/badge.svg)](https://github.com/turinglambdaai/pcap/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

一个纯 Racket 的经典 pcap 抓包文件（libpcap/tcpdump 格式）读取器，可解析
Ethernet II（含 802.1Q/802.1ad VLAN 标签）、IPv4、IPv6（仅固定头）、TCP
与 UDP。无 FFI、无系统依赖——只依赖 `base`。

## 安装

```sh
raco pkg install pcap
```

## 示例

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

## 范围

- 仅支持经典 pcap，覆盖全部四种 magic 变体（两种字节序、两种时间戳
  精度）：

  | Magic（磁盘上的字节）  | 字节序        | 时间戳单位     |
  | ---------------------- | ------------- | -------------- |
  | `a1 b2 c3 d4`          | big-endian    | microseconds   |
  | `d4 c3 b2 a1`          | little-endian | microseconds   |
  | `a1 b2 3c 4d`          | big-endian    | nanoseconds    |
  | `4d 3c b2 a1`          | little-endian | nanoseconds    |

- **pcapng 不在范围内**：把 pcapng 文件喂给任何读取器都会抛出
  `exn:fail`，并附 "bad magic number" 消息。
- 对每个数据包，读取器保留两个长度：`packet-data` 恰好持有
  `incl_len` 个捕获字节，而 `packet-orig-len` 在快照长度截断数据包时
  保留原始线上长度。
- 解析范围涵盖 Ethernet II（802.1Q/802.1ad VLAN 标签，含 QinQ）、
  IPv4（带选项）、IPv6 固定头（不解析扩展头）、TCP 与 UDP。不校验
  校验和。

[参考手册](pcap/scribblings/pcap.scrbl)是包的一部分；安装后用
`raco docs pcap` 阅读。

## 许可证

[MIT](LICENSE)
