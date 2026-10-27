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

下面的示例在内存中解析**合成**的经典 pcap 文件，不需要抓包权限、
外部文件或真实网卡。

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

读取你自己的经典 pcap 文件可使用 `(pcap-read-file "capture.pcap")`。
[可执行入门示例](examples/quickstart.rkt)还会断言数据包数量、时间戳、
原始长度、EtherType 和载荷解码结果。

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

## API 文档与开发

[权威 Scribble API 手册](pcap/scribblings/pcap.scrbl)定义读取器契约、
协议解析、错误行为及不支持的 pcapng 格式。现有测试覆盖四种 magic、
截断及损坏输入。在安装 Racket 后，从仓库根目录运行：

```sh
raco pkg install --auto --link "$(pwd)"
raco test -p pcap
racket examples/quickstart.rkt
raco setup --check-pkg-deps -l pcap
```

CI 在 Linux、macOS、Windows 上执行以上检查。反馈时请提供合成的
脱敏最小样例和 Racket 版本，通过
[GitHub Issues](https://github.com/turinglambdaai/pcap/issues) 提交。

## 许可证

[MIT](LICENSE)
