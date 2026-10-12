#lang racket/base

;; Unit tests for the pcap package.  Every capture and frame below is
;; synthesized byte-by-byte; comments map each field.

(require racket/file
         racket/list
         racket/match
         rackunit
         pcap)

;; ---- byte-building helpers (network byte order) ----------------------

(define (u16-bytes v)
  (bytes (bitwise-and (arithmetic-shift v -8) #xff)
         (bitwise-and v #xff)))

(define (u32-bytes v)
  (bytes (bitwise-and (arithmetic-shift v -24) #xff)
         (bitwise-and (arithmetic-shift v -16) #xff)
         (bitwise-and (arithmetic-shift v -8) #xff)
         (bitwise-and v #xff)))

(define (u16-bytes* v big-endian?)
  (define be (u16-bytes v))
  (if big-endian? be (bytes (bytes-ref be 1) (bytes-ref be 0))))

(define (u32-bytes* v big-endian?)
  (define be (u32-bytes v))
  (if big-endian?
      be
      (bytes (bytes-ref be 3) (bytes-ref be 2) (bytes-ref be 1) (bytes-ref be 0))))

;; ---- the four classic pcap magic numbers ------------------------------
;; Octet sequences as they appear at the start of the file
;; (draft-ietf-opsawg-pcap section 4.1).

(define magic-be-us (bytes #xa1 #xb2 #xc3 #xd4)) ; big endian,    microseconds
(define magic-be-ns (bytes #xa1 #xb2 #x3c #x4d)) ; big endian,    nanoseconds
(define magic-le-us (bytes #xd4 #xc3 #xb2 #xa1)) ; little endian, microseconds
(define magic-le-ns (bytes #x4d #x3c #xb2 #xa1)) ; little endian, nanoseconds

;; ---- capture-building helpers -----------------------------------------

;; Global header (24 octets).
(define (global-header-bs magic big-endian? snaplen)
  (bytes-append
   magic                       ; magic number (encodes endianness + resolution)
   (u16-bytes* 2 big-endian?)  ; version-major = 2
   (u16-bytes* 4 big-endian?)  ; version-minor = 4
   (u32-bytes* 0 big-endian?)  ; thiszone (reserved; ignored)
   (u32-bytes* 0 big-endian?)  ; sigfigs (reserved; ignored)
   (u32-bytes* snaplen big-endian?) ; snaplen
   (u32-bytes* 1 big-endian?)))     ; network = 1 (LINKTYPE_ETHERNET)

;; Packet record header (16 octets) plus data.  incl-len defaults to
;; the data length but can be overridden to model corrupt/truncated
;; files.
(define (record-bs ts-sec ts-frac data orig-len big-endian?
                   [incl-len (bytes-length data)])
  (bytes-append
   (u32-bytes* ts-sec big-endian?)      ; ts_sec
   (u32-bytes* ts-frac big-endian?)     ; ts_usec / ts_nsec
   (u32-bytes* incl-len big-endian?)    ; incl_len (captured length)
   (u32-bytes* orig-len big-endian?)    ; orig_len (wire length)
   data))

;; ---- hand-built protocol frames ----------------------------------------

;; Ethernet/IPv4/TCP: 192.168.1.1:52341 -> 192.168.1.2:443, bare SYN.
(define eth-tcp-frame
  (bytes-append
   ;; Ethernet II header (14 octets)
   (bytes #xaa #xbb #xcc #xdd #xee #xff) ; destination MAC aa:bb:cc:dd:ee:ff
   (bytes #x11 #x22 #x33 #x44 #x55 #x66) ; source MAC 11:22:33:44:55:66
   (bytes #x08 #x00)                     ; EtherType 0x0800 = IPv4
   ;; IPv4 header (20 octets, no options)
   (bytes #x45)                  ; version 4, IHL 5 -> 20-byte header
   (bytes #x00)                  ; DSCP 0, ECN 0
   (u16-bytes 40)                ; total length: 20 (IP) + 20 (TCP)
   (bytes #x12 #x34)             ; identification
   (bytes #x40 #x00)             ; flags DF (0x4000), fragment offset 0
   (bytes #x40)                  ; TTL 64
   (bytes #x06)                  ; protocol 6 = TCP
   (bytes #x00 #x00)             ; header checksum (not validated here)
   (bytes #xc0 #xa8 #x01 #x01)   ; source address 192.168.1.1
   (bytes #xc0 #xa8 #x01 #x02)   ; destination address 192.168.1.2
   ;; TCP header (20 octets, no options)
   (u16-bytes 52341)             ; source port 0xcc75
   (u16-bytes 443)               ; destination port 0x01bb
   (u32-bytes 1000)              ; sequence number
   (u32-bytes 0)                 ; acknowledgment number
   (bytes #x50)                  ; data offset 5 -> 20-byte header
   (bytes #x02)                  ; flags: SYN
   (u16-bytes 64240)             ; window
   (bytes #x00 #x00)             ; checksum (not validated)
   (bytes #x00 #x00)))           ; urgent pointer

;; A 29-octet DNS query: header plus QNAME for "example.com", type A, class IN.
(define dns-query
  (bytes-append
   (bytes #x12 #x34)   ; transaction id
   (bytes #x01 #x00)   ; flags: standard query, recursion desired
   (bytes #x00 #x01)   ; qdcount = 1
   (bytes #x00 #x00)   ; ancount = 0
   (bytes #x00 #x00)   ; nscount = 0
   (bytes #x00 #x00)   ; arcount = 0
   (bytes #x07 #x65 #x78 #x61 #x6d #x70 #x6c #x65) ; label "example"
   (bytes #x03 #x63 #x6f #x6d)                     ; label "com"
   (bytes #x00)        ; root label
   (bytes #x00 #x01)   ; qtype = A
   (bytes #x00 #x01))) ; qclass = IN

;; Ethernet/IPv4/UDP: 192.168.1.1:54321 -> 192.168.1.2:53 (the DNS query).
(define eth-udp-frame
  (bytes-append
   ;; Ethernet II header (14 octets)
   (bytes #xaa #xbb #xcc #xdd #xee #xff) ; destination MAC
   (bytes #x11 #x22 #x33 #x44 #x55 #x66) ; source MAC
   (bytes #x08 #x00)                     ; EtherType 0x0800 = IPv4
   ;; IPv4 header (20 octets, no options)
   (bytes #x45)                  ; version 4, IHL 5
   (bytes #x00)                  ; DSCP 0, ECN 0
   (u16-bytes (+ 20 8 (bytes-length dns-query))) ; total length = 57
   (bytes #x12 #x35)             ; identification
   (bytes #x40 #x00)             ; flags DF, fragment offset 0
   (bytes #x40)                  ; TTL 64
   (bytes #x11)                  ; protocol 17 = UDP
   (bytes #x00 #x00)             ; header checksum (not validated)
   (bytes #xc0 #xa8 #x01 #x01)   ; source address 192.168.1.1
   (bytes #xc0 #xa8 #x01 #x02)   ; destination address 192.168.1.2
   ;; UDP header (8 octets)
   (u16-bytes 54321)             ; source port 0xd431
   (u16-bytes 53)                ; destination port 0x0035
   (u16-bytes (+ 8 (bytes-length dns-query))) ; length = 37
   (bytes #x00 #x00)             ; checksum (0 = absent for IPv4)
   dns-query))

;; Ethernet/IPv6/UDP: [2001:db8::1]:5353 -> [fe80::2]:53 (the DNS query).
(define eth-ipv6-udp-frame
  (bytes-append
   ;; Ethernet II header (14 octets)
   (bytes #x33 #x33 #x00 #x00 #x00 #x02) ; destination MAC 33:33:00:00:00:02
   (bytes #x11 #x22 #x33 #x44 #x55 #x66) ; source MAC
   (bytes #x86 #xdd)                     ; EtherType 0x86dd = IPv6
   ;; IPv6 fixed header (40 octets)
   (bytes #x60 #x00 #x00 #x00) ; version 6, traffic class 0, flow label 0
   (u16-bytes (+ 8 (bytes-length dns-query))) ; payload length = the UDP datagram
   (bytes #x11)                ; next header 17 = UDP (no extension headers)
   (bytes #x40)                ; hop limit 64
   (bytes #x20 #x01 #x0d #xb8  ; source address 2001:db8::1
          #x00 #x00 #x00 #x00
          #x00 #x00 #x00 #x00
          #x00 #x00 #x00 #x01)
   (bytes #xfe #x80 #x00 #x00  ; destination address fe80::2
          #x00 #x00 #x00 #x00
          #x00 #x00 #x00 #x00
          #x00 #x00 #x00 #x02)
   ;; UDP header (8 octets)
   (u16-bytes 5353)            ; source port
   (u16-bytes 53)              ; destination port
   (u16-bytes (+ 8 (bytes-length dns-query))) ; length
   (bytes #x00 #x00)           ; checksum (not validated)
   dns-query))

;; ---- 1. golden capture, all four magic variants ------------------------
;;
;; Packet 1: the full Ethernet/IPv4/TCP frame at 1700000000 + 500000
;;           fractional units.
;; Packet 2: the full Ethernet/IPv4/UDP frame at 1700000001 + 1
;;           fractional unit.

(define (golden-capture magic big-endian? nanosecond?)
  (bytes-append
   (global-header-bs magic big-endian? 65535)
   (record-bs 1700000000 500000
              eth-tcp-frame (bytes-length eth-tcp-frame) big-endian?)
   (record-bs 1700000001 1
              eth-udp-frame (bytes-length eth-udp-frame) big-endian?)))

(define variants
  (list (list "BE us" magic-be-us #t #f)
        (list "BE ns" magic-be-ns #t #t)
        (list "LE us" magic-le-us #f #f)
        (list "LE ns" magic-le-ns #f #t)))

(define (frac->seconds v nanosecond?)
  (/ v (if nanosecond? 1000000000 1000000)))

(for ((variant (in-list variants)))
  (match-define (list name magic big-endian? nanosecond?) variant)
  (define capture (golden-capture magic big-endian? nanosecond?))

  ;; Global header fields, read via pcap-read-header.
  (define header (pcap-read-header (open-input-bytes capture)))
  (check-equal? (pcap-header-link-type header) 1
                (format "~a: link type" name))
  (check-equal? (pcap-header-snaplen header) 65535
                (format "~a: snaplen" name))

  ;; Packets read back in order with exact rational timestamps.
  (define pkts (pcap-read-bytes capture))
  (check-equal? (length pkts) 2 (format "~a: packet count" name))
  (match-define (list p1 p2) pkts)
  (check-equal? (packet-timestamp p1)
                (+ 1700000000 (frac->seconds 500000 nanosecond?))
                (format "~a: packet 1 timestamp" name))
  (check-equal? (packet-timestamp p2)
                (+ 1700000001 (frac->seconds 1 nanosecond?))
                (format "~a: packet 2 timestamp" name))
  (check-pred exact? (packet-timestamp p1)
              (format "~a: timestamp is exact" name))
  (check-equal? (packet-link-type p1) 1 (format "~a: packet link type" name))
  (check-equal? (packet-data p1) eth-tcp-frame (format "~a: packet 1 data" name))
  (check-equal? (packet-data p2) eth-udp-frame (format "~a: packet 2 data" name))
  (check-equal? (packet-orig-len p1) (bytes-length eth-tcp-frame)
                (format "~a: packet 1 orig-len" name))
  (check-equal? (packet-orig-len p2) (bytes-length eth-udp-frame)
                (format "~a: packet 2 orig-len" name)))

;; snaplen truncation: data holds incl_len bytes, orig-len is preserved.
(define (truncated-capture magic big-endian?)
  (bytes-append
   (global-header-bs magic big-endian? 40) ; snaplen = 40
   (record-bs 1700000002 999999
              (subbytes eth-udp-frame 0 40)
              (bytes-length eth-udp-frame)
              big-endian?)))

(for ((magic (in-list (list magic-be-us magic-be-ns magic-le-us magic-le-ns)))
      (big-endian? (in-list (list #t #t #f #f)))
      (nanosecond? (in-list (list #f #t #f #t))))
  (define pkt (first (pcap-read-bytes (truncated-capture magic big-endian?))))
  (check-equal? (bytes-length (packet-data pkt)) 40
                "truncated capture: data holds incl_len bytes")
  (check-equal? (packet-data pkt) (subbytes eth-udp-frame 0 40)
                "truncated capture: data content")
  (check-equal? (packet-orig-len pkt) (bytes-length eth-udp-frame)
                "truncated capture: orig-len preserved")
  (check-equal? (packet-timestamp pkt)
                (+ 1700000002 (frac->seconds 999999 nanosecond?))
                "truncated capture: timestamp"))

;; ---- 2. dissection: Ethernet/IPv4/TCP and Ethernet/IPv4/UDP ------------

(define tcp-eth (decode-ethernet eth-tcp-frame))
(check-equal? (ethernet-frame-dst tcp-eth) "aa:bb:cc:dd:ee:ff")
(check-equal? (ethernet-frame-src tcp-eth) "11:22:33:44:55:66")
(check-equal? (ethernet-frame-ether-type tcp-eth) #x0800)
(check-false (ethernet-frame-tagged? tcp-eth))
(check-equal? (ethernet-frame-payload tcp-eth) (subbytes eth-tcp-frame 14))

(define ip (decode-ipv4 (ethernet-frame-payload tcp-eth)))
(check-equal? (ipv4-header-src ip) "192.168.1.1")
(check-equal? (ipv4-header-dst ip) "192.168.1.2")
(check-equal? (ipv4-header-protocol ip) 6)
(check-equal? (ipv4-header-ttl ip) 64)
(check-equal? (ipv4-header-options ip) #"")
(check-equal? (ipv4-header-payload ip) (subbytes eth-tcp-frame 34))

(define tcp (decode-tcp (ipv4-header-payload ip)))
(check-equal? (tcp-header-src-port tcp) 52341)
(check-equal? (tcp-header-dst-port tcp) 443)
(check-equal? (tcp-header-seq tcp) 1000)
(check-equal? (tcp-header-ack tcp) 0)
(check-equal? (tcp-header-flags tcp) #x02) ; SYN
(check-equal? (tcp-header-payload tcp) #"")

(define udp-eth (decode-ethernet eth-udp-frame))
(check-equal? (ethernet-frame-ether-type udp-eth) #x0800)
(define uip (decode-ipv4 (ethernet-frame-payload udp-eth)))
(check-equal? (ipv4-header-protocol uip) 17)
(check-equal? (ipv4-header-payload uip) (subbytes eth-udp-frame 34))

(define udp (decode-udp (ipv4-header-payload uip)))
(check-equal? (udp-header-src-port udp) 54321)
(check-equal? (udp-header-dst-port udp) 53)
(check-equal? (udp-header-payload udp) dns-query)

;; IPv4 with options: IHL 6 -> 24-byte header, 4 option octets.
(define ip-options-frame
  (bytes-append
   (bytes #x46)                  ; version 4, IHL 6 -> 24-byte header
   (bytes #x00)                  ; DSCP/ECN
   (u16-bytes 24)                ; total length (header only)
   (bytes #x00 #x01)             ; identification
   (bytes #x40 #x00)             ; flags DF, offset 0
   (bytes #x7f)                  ; TTL 127
   (bytes #x01)                  ; protocol 1 = ICMP
   (bytes #x00 #x00)             ; checksum
   (bytes #x0a #x00 #x00 #x01)   ; source 10.0.0.1
   (bytes #x0a #x00 #x00 #x02)   ; destination 10.0.0.2
   (bytes #x01 #x01 #x01 #x00))) ; options, terminated by EOL
(define ipo (decode-ipv4 ip-options-frame))
(check-equal? (ipv4-header-src ipo) "10.0.0.1")
(check-equal? (ipv4-header-ttl ipo) 127)
(check-equal? (ipv4-header-options ipo) (bytes #x01 #x01 #x01 #x00))
(check-equal? (ipv4-header-payload ipo) #"")

;; decode-packet nests Ethernet -> IPv4 -> TCP.
(define nested (decode-packet (packet 0 1 eth-tcp-frame (bytes-length eth-tcp-frame))))
(check-pred ethernet-frame? nested)
(define nested-ip (ethernet-frame-payload nested))
(check-pred ipv4-header? nested-ip)
(check-equal? (ipv4-header-src nested-ip) "192.168.1.1")
(check-pred tcp-header? (ipv4-header-payload nested-ip))
(check-equal? (tcp-header-dst-port (ipv4-header-payload nested-ip)) 443)

;; ---- 3. VLAN-tagged frames ---------------------------------------------

;; 802.1Q, VLAN ID 100.
(define vlan-frame
  (bytes-append
   (bytes #xaa #xbb #xcc #xdd #xee #xff) ; destination MAC
   (bytes #x11 #x22 #x33 #x44 #x55 #x66) ; source MAC
   (bytes #x81 #x00)                     ; EtherType 0x8100 = 802.1Q tag
   (bytes #x00 #x64)                     ; TCI: priority 0, VLAN ID 100
   (bytes #x08 #x00)                     ; inner EtherType: IPv4
   (subbytes eth-tcp-frame 14)))         ; the IPv4 packet, unchanged
(define vlan-eth (decode-ethernet vlan-frame))
(check-true (ethernet-frame-tagged? vlan-eth))
(check-equal? (ethernet-frame-ether-type vlan-eth) #x0800)
(check-equal? (ethernet-frame-payload vlan-eth) (subbytes eth-tcp-frame 14))
(define vlan-nested (decode-packet (packet 0 1 vlan-frame (bytes-length vlan-frame))))
(check-pred tcp-header?
            (ipv4-header-payload (ethernet-frame-payload vlan-nested)))

;; QinQ: 802.1ad provider tag (VLAN 10) around an 802.1Q tag (VLAN 100).
(define qinq-frame
  (bytes-append
   (subbytes vlan-frame 0 12)
   (bytes #x88 #xa8)     ; EtherType 0x88a8 = 802.1ad
   (bytes #x00 #x0a)     ; outer TCI: VLAN ID 10
   (bytes #x81 #x00)     ; inner 802.1Q tag
   (bytes #x00 #x64)     ; TCI: VLAN ID 100
   (bytes #x08 #x00)     ; inner EtherType: IPv4
   (subbytes eth-tcp-frame 14)))
(define qinq-eth (decode-ethernet qinq-frame))
(check-true (ethernet-frame-tagged? qinq-eth))
(check-equal? (ethernet-frame-ether-type qinq-eth) #x0800)
(check-equal? (ethernet-frame-payload qinq-eth) (subbytes eth-tcp-frame 14))

;; ---- 4. errors ----------------------------------------------------------

;; Bad magic number (including pcapng's file block type).
(check-exn #rx"bad magic number"
           (λ () (pcap-read-bytes (bytes-append (bytes #x0a #x0b #x0c #x0d)
                                                (make-bytes 20)))))
(check-exn #rx"pcapng"
           (λ () (pcap-read-bytes (bytes-append (bytes #x0a #x0d #x0d #x0a)
                                                (make-bytes 20)))))
(check-exn exn:fail? (λ () (pcap-read-bytes (make-bytes 24))))

;; Truncated global header.
(check-exn #rx"truncated global header" (λ () (pcap-read-bytes (bytes))))
(check-exn #rx"truncated global header" (λ () (pcap-read-bytes (bytes 1 2 3))))
(check-exn #rx"truncated global header" (λ () (pcap-read-bytes (make-bytes 23))))

;; Truncated packet record header (record starts but is cut short).
(define gh (global-header-bs magic-be-us #t 65535))
(check-exn #rx"truncated packet record header"
           (λ () (pcap-read-bytes (bytes-append gh (make-bytes 10)))))
(check-exn #rx"truncated packet record header"
           (λ () (pcap-read-bytes (bytes-append gh (make-bytes 15)))))

;; Truncated packet data: the record header claims more data than follows.
(check-exn #rx"truncated packet data"
           (λ () (pcap-read-bytes
                  (bytes-append gh (record-bs 1700000000 0 (make-bytes 10) 100 #t 100)))))

;; Implausibly large captured length (corrupt file, guarded by a
;; safety limit so we never try to allocate 4 GiB).
(check-exn #rx"implausibly large"
           (λ () (pcap-read-bytes
                  (bytes-append gh (record-bs 1700000000 0 (make-bytes 4) 4 #t #xffffffff)))))

;; Dissection errors.
(check-exn #rx"truncated Ethernet frame" (λ () (decode-ethernet (make-bytes 13))))
(check-exn #rx"truncated IPv4 header" (λ () (decode-ipv4 (make-bytes 19))))
(check-exn #rx"not an IPv4 packet"
           (λ () (decode-ipv4 (bytes-append (bytes #x60) (make-bytes 39)))))
(check-exn #rx"truncated TCP header" (λ () (decode-tcp (make-bytes 19))))
(check-exn #rx"truncated UDP header" (λ () (decode-udp (make-bytes 7))))
(check-exn #rx"unsupported link type"
           (λ () (decode-packet (packet 0 113 eth-tcp-frame
                                        (bytes-length eth-tcp-frame)))))

;; ---- 5. mixed capture ---------------------------------------------------
;;
;; Three packets of different protocols (TCP, UDP, IPv6/UDP) in one
;; nanosecond-resolution little-endian capture, read back in order.

(define mixed-capture
  (bytes-append
   (global-header-bs magic-le-ns #f 65535)
   (record-bs 1000000000 100000000 eth-tcp-frame (bytes-length eth-tcp-frame) #f)
   (record-bs 1000000000 200000000 eth-udp-frame (bytes-length eth-udp-frame) #f)
   (record-bs 1000000000 300000000 eth-ipv6-udp-frame (bytes-length eth-ipv6-udp-frame) #f)))

(define mixed (pcap-read-bytes mixed-capture))
(check-equal? (length mixed) 3 "mixed capture: packet count")

;; Packets come back in capture order with exact nanosecond timestamps.
(check-equal? (packet-timestamp (first mixed))  (+ 1000000000 1/10) "mixed: ts 1")
(check-equal? (packet-timestamp (second mixed)) (+ 1000000000 1/5)  "mixed: ts 2")
(check-equal? (packet-timestamp (third mixed))  (+ 1000000000 3/10) "mixed: ts 3")
(check-equal? (packet-data (first mixed))  eth-tcp-frame      "mixed: data 1")
(check-equal? (packet-data (second mixed)) eth-udp-frame      "mixed: data 2")
(check-equal? (packet-data (third mixed))  eth-ipv6-udp-frame "mixed: data 3")

;; ...and dissect to TCP, UDP, and IPv6/UDP respectively.
(define m1 (decode-packet (first mixed)))
(check-pred tcp-header? (ipv4-header-payload (ethernet-frame-payload m1)))
(check-equal? (tcp-header-flags (ipv4-header-payload (ethernet-frame-payload m1))) #x02)

(define m2 (decode-packet (second mixed)))
(check-pred udp-header? (ipv4-header-payload (ethernet-frame-payload m2)))
(check-equal? (udp-header-dst-port (ipv4-header-payload (ethernet-frame-payload m2))) 53)

(define m3 (decode-packet (third mixed)))
(define m3-ip (ethernet-frame-payload m3))
(check-pred ipv6-header? m3-ip)
(check-equal? (ipv6-header-src m3-ip) "2001:db8::1")
(check-equal? (ipv6-header-dst m3-ip) "fe80::2")
(check-equal? (ipv6-header-next-header m3-ip) 17)
(check-equal? (ipv6-header-hop-limit m3-ip) 64)
(check-pred udp-header? (ipv6-header-payload m3-ip))
(check-equal? (udp-header-payload (ipv6-header-payload m3-ip)) dns-query)

;; ---- file I/O round trip ------------------------------------------------

;; pcap-read-file agrees with pcap-read-bytes.
(define tmp-pcap (make-temporary-file "pcap-test-~a.pcap"))
(call-with-output-file tmp-pcap
  (λ (out) (write-bytes mixed-capture out))
  #:exists 'truncate)
(check-equal? (pcap-read-file (path->string tmp-pcap)) mixed)
(delete-file tmp-pcap)
