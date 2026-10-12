#lang racket/base

;; Dissection of common packet formats on top of the pcap reader:
;; Ethernet II (including 802.1Q / 802.1ad VLAN tags), IPv4, IPv6
;; (fixed header only -- extension headers are not parsed), TCP, and
;; UDP.
;;
;; All multi-octet fields are read in network byte order (big endian).
;; Checksums are not validated.

(require racket/bytes
         racket/contract
         racket/format
         racket/string
         "reader.rkt")

;; ---- data structures -------------------------------------------------

(struct ethernet-frame (dst src ether-type payload tagged?) #:transparent)
(struct ipv4-header (src dst protocol ttl options payload) #:transparent)
(struct ipv6-header (src dst next-header hop-limit payload) #:transparent)
(struct tcp-header (src-port dst-port seq ack flags payload) #:transparent)
(struct udp-header (src-port dst-port payload) #:transparent)

;; A decoded payload: raw bytes, or the next decoded layer when the
;; dissection is nested (as produced by decode-packet).
(define layer/c
  (or/c bytes? ipv4-header? ipv6-header? tcp-header? udp-header?))

;; ---- protocol constants ----------------------------------------------

(define ethertype-ipv4       #x0800)
(define ethertype-vlan       #x8100) ; 802.1Q
(define ethertype-ipv6       #x86dd)
(define ethertype-vlan-qinq  #x88a8) ; 802.1ad provider tag
(define ethertype-vlan-9100  #x9100) ; legacy QinQ seen in the wild

(define proto-tcp 6)
(define proto-udp 17)

(define link-type-ethernet 1) ; LINKTYPE_ETHERNET

;; ---- byte helpers ----------------------------------------------------

(define (u16 bs off) (integer-bytes->integer bs #f #t off (+ off 2)))
(define (u32* bs off) (integer-bytes->integer bs #f #t off (+ off 4)))

;; Formats six octets starting at `start` as "aa:bb:cc:dd:ee:ff".
(define (mac->string bs start)
  (string-join
   (for/list ((i (in-range 6)))
     (~r (bytes-ref bs (+ start i)) #:base 16 #:min-width 2 #:pad-string "0"))
   ":"))

;; Formats four octets starting at `start` in dotted-quad notation.
(define (ipv4->string bs start)
  (string-join
   (for/list ((i (in-range 4)))
     (number->string (bytes-ref bs (+ start i))))
   "."))

;; Formats 16 octets starting at `start` per RFC 5952 (lowercase hex,
;; longest zero run of at least two groups compressed to "::", ties to
;; the leftmost run).
(define (ipv6->string bs start)
  (define groups
    (for/list ((i (in-range 8)))
      (~r (u16 bs (+ start (* 2 i))) #:base 16)))
  (define-values (zero-start zero-len) (longest-zero-run groups))
  (cond
    ((not zero-start) (string-join groups ":"))
    ((= zero-len 8) "::")
    ;; Join the groups before and after the zero run and splice them
    ;; around a "::".
    (else
     (string-append (join-groups groups 0 zero-start)
                    "::"
                    (join-groups groups (+ zero-start zero-len) 8)))))

;; Joins groups[lo .. hi) with colons.
(define (join-groups groups lo hi)
  (string-join (for/list ((i (in-range lo hi))) (list-ref groups i)) ":"))

;; Returns (values start length) of the longest run of "0" groups;
;; ties go to the leftmost run.  Returns (values #f 0) if none.
(define (longest-zero-run groups)
  (let loop ((i 0) (best-start #f) (best-len 0))
    (cond
      ((>= i 8) (values best-start best-len))
      ((string=? (list-ref groups i) "0")
       (define end
         (let scan ((j i))
           (if (and (< j 8) (string=? (list-ref groups j) "0"))
               (scan (add1 j))
               j)))
       (define len (- end i))
       (if (> len best-len)
           (loop end i len)
           (loop end best-start best-len)))
      (else (loop (add1 i) best-start best-len)))))

;; ---- dissection -------------------------------------------------------

;; Decodes an Ethernet II frame.  VLAN tags (802.1Q, 802.1ad, and the
;; legacy 0x9100 form, including QinQ stacks) are skipped: `ether-type`
;; reports the final inner EtherType and `tagged?` reports whether any
;; VLAN tag was present.
(define (decode-ethernet bs)
  (define len (bytes-length bs))
  (unless (>= len 14)
    (error 'decode-ethernet
           "truncated Ethernet frame: expected at least 14 bytes, found ~a" len))
  (let loop ((off 0) (tagged? #f))
    (define ethertype (u16 bs (+ off 12)))
    (cond
      ((memv ethertype (list ethertype-vlan ethertype-vlan-qinq ethertype-vlan-9100))
       (unless (>= len (+ off 18))
         (error 'decode-ethernet
                "truncated 802.1Q VLAN tag: expected at least ~a bytes, found ~a"
                (+ off 18) len))
       (loop (+ off 4) #t))
      (else
       (ethernet-frame (mac->string bs 0)
                       (mac->string bs 6)
                       ethertype
                       (subbytes bs (+ off 14))
                       tagged?)))))

;; Decodes an IPv4 packet.  The payload is trimmed to the IP total
;; length field, which discards Ethernet padding on small frames; a
;; capture truncated below the declared total length yields the
;; remaining bytes.
(define (decode-ipv4 bs)
  (define len (bytes-length bs))
  (unless (>= len 20)
    (error 'decode-ipv4
           "truncated IPv4 header: expected at least 20 bytes, found ~a" len))
  (define b0 (bytes-ref bs 0))
  (define version (arithmetic-shift b0 -4))
  (unless (= version 4)
    (error 'decode-ipv4 "not an IPv4 packet: version field is ~a" version))
  (define ihl (bitwise-and b0 #x0f))
  (define header-len (* ihl 4))
  (unless (>= header-len 20)
    (error 'decode-ipv4
           "malformed IPv4 header: IHL ~a yields a ~a-byte header, fewer than the minimum 20"
           ihl header-len))
  (unless (<= header-len len)
    (error 'decode-ipv4
           "truncated IPv4 header: header length ~a exceeds the ~a available bytes"
           header-len len))
  (define total-len (u16 bs 2))
  (unless (>= total-len header-len)
    (error 'decode-ipv4
           "malformed IPv4 packet: total length ~a is shorter than the ~a-byte header"
           total-len header-len))
  (ipv4-header (ipv4->string bs 12)
               (ipv4->string bs 16)
               (bytes-ref bs 9)
               (bytes-ref bs 8)
               (subbytes bs 20 header-len)
               (subbytes bs header-len (min total-len len))))

;; Decodes the fixed 40-octet IPv6 header.  Extension headers are not
;; parsed: `next-header` is the raw protocol number and the payload is
;; everything past the fixed header.
(define (decode-ipv6 bs)
  (define len (bytes-length bs))
  (unless (>= len 40)
    (error 'decode-ipv6
           "truncated IPv6 header: expected at least 40 bytes, found ~a" len))
  (define version (arithmetic-shift (bytes-ref bs 0) -4))
  (unless (= version 6)
    (error 'decode-ipv6 "not an IPv6 packet: version field is ~a" version))
  (ipv6-header (ipv6->string bs 8)
               (ipv6->string bs 24)
               (bytes-ref bs 6)
               (bytes-ref bs 7)
               (subbytes bs 40)))

;; Decodes a TCP segment.  `flags` holds the nine meaningful flag bits
;; (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN); the data-offset nibble
;; is consumed while computing the header length.
(define (decode-tcp bs)
  (define len (bytes-length bs))
  (unless (>= len 20)
    (error 'decode-tcp
           "truncated TCP header: expected at least 20 bytes, found ~a" len))
  (define header-len (* (arithmetic-shift (bytes-ref bs 12) -4) 4))
  (unless (>= header-len 20)
    (error 'decode-tcp
           "malformed TCP header: data offset yields a ~a-byte header, fewer than the minimum 20"
           header-len))
  (unless (<= header-len len)
    (error 'decode-tcp
           "truncated TCP header: data offset ~a exceeds the ~a available bytes"
           header-len len))
  (tcp-header (u16 bs 0)
              (u16 bs 2)
              (u32* bs 4)
              (u32* bs 8)
              (bitwise-and (u16 bs 12) #x01ff)
              (subbytes bs header-len)))

;; Decodes a UDP datagram.  The payload is trimmed to the UDP length
;; field, discarding padding; a capture truncated below the declared
;; length yields the remaining bytes.
(define (decode-udp bs)
  (define len (bytes-length bs))
  (unless (>= len 8)
    (error 'decode-udp
           "truncated UDP header: expected at least 8 bytes, found ~a" len))
  (define declared-len (u16 bs 4))
  (unless (>= declared-len 8)
    (error 'decode-udp
           "malformed UDP datagram: length field is ~a, fewer than the minimum 8"
           declared-len))
  (udp-header (u16 bs 0)
              (u16 bs 2)
              (subbytes bs 8 (min declared-len len))))

;; Convenience: dissects a packet from an Ethernet capture into a
;; nested ethernet-frame whose payload is an ipv4-header or
;; ipv6-header, whose payload in turn is a tcp-header or udp-header
;; when recognizable, and raw bytes otherwise.  If a transport header
;; is truncated or malformed it is left undecoded rather than raising.
(define (decode-packet pkt)
  (define link-type (packet-link-type pkt))
  (unless (= link-type link-type-ethernet)
    (error 'decode-packet
           "unsupported link type ~a: only Ethernet (link type 1) captures are supported"
           link-type))
  (define eth (decode-ethernet (packet-data pkt)))
  (define l3
    (case (ethernet-frame-ether-type eth)
      ((#x0800) (decode-ipv4 (ethernet-frame-payload eth)))
      ((#x86dd) (decode-ipv6 (ethernet-frame-payload eth)))
      (else #f)))
  (define nested
    (cond
      ((ipv4-header? l3)
       (struct-copy ipv4-header l3
                    (payload (decode-l4 (ipv4-header-protocol l3)
                                        (ipv4-header-payload l3)))))
      ((ipv6-header? l3)
       (struct-copy ipv6-header l3
                    (payload (decode-l4 (ipv6-header-next-header l3)
                                        (ipv6-header-payload l3)))))
      (else #f)))
  (if nested
      (struct-copy ethernet-frame eth (payload nested))
      eth))

;; decode-l4 : exact-nonnegative-integer? bytes? -> layer/c
(define (decode-l4 protocol bs)
  (case protocol
    ((6) (try-decode decode-tcp bs))
    ((17) (try-decode decode-udp bs))
    (else bs)))

(define (try-decode decode bs)
  (with-handlers ((exn:fail? (λ (_) bs)))
    (decode bs)))

;; ---- exports ----------------------------------------------------------

(provide
 (contract-out
  (struct ethernet-frame
    ((dst string?)
     (src string?)
     (ether-type exact-nonnegative-integer?)
     (payload layer/c)
     (tagged? boolean?)))
  (struct ipv4-header
    ((src string?)
     (dst string?)
     (protocol exact-nonnegative-integer?)
     (ttl exact-nonnegative-integer?)
     (options bytes?)
     (payload layer/c)))
  (struct ipv6-header
    ((src string?)
     (dst string?)
     (next-header exact-nonnegative-integer?)
     (hop-limit exact-nonnegative-integer?)
     (payload layer/c)))
  (struct tcp-header
    ((src-port exact-nonnegative-integer?)
     (dst-port exact-nonnegative-integer?)
     (seq exact-nonnegative-integer?)
     (ack exact-nonnegative-integer?)
     (flags exact-nonnegative-integer?)
     (payload layer/c)))
  (struct udp-header
    ((src-port exact-nonnegative-integer?)
     (dst-port exact-nonnegative-integer?)
     (payload layer/c)))
  (decode-ethernet (-> bytes? ethernet-frame?))
  (decode-ipv4 (-> bytes? ipv4-header?))
  (decode-ipv6 (-> bytes? ipv6-header?))
  (decode-tcp (-> bytes? tcp-header?))
  (decode-udp (-> bytes? udp-header?))
  (decode-packet (-> packet? ethernet-frame?))))
