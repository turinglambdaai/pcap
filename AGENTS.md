# AGENTS.md

经典 pcap 捕获文件（libpcap/tcpdump 格式）的纯 Racket 读取与协议剖析：Ethernet II（含 VLAN）、IPv4、IPv6（仅头）、TCP、UDP（MIT）。

## 结构

Multi-collection 包：collection 即 `pcap/` 子目录，scribblings 声明在 `pcap/info.rkt`（collection 级）。

## 常用命令

```bash
raco pkg install --auto --link "$(pwd)"
raco test -p pcap
```

## 验证与发版

- CI（`ci.yml`）：即上面两条命令，三平台跑。
- 发版 = tag `v<版本>` + CHANGELOG 同步；catalog 侧为手动提交（pkgd）。

## 仓库特定规矩

- 无 FFI、无系统依赖，只依赖 `base`——不要为「性能」引入 libpcap 破坏这条（README 明文承诺）。
