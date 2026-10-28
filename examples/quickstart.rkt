#lang racket/base
;; Minimal in-memory classic pcap (big-endian, microsecond timestamps).
;; No capture files, network privileges, libpcap, or hardware needed.
(require pcap)

(define frame
  (bytes #xaa #xbb #xcc #xdd #xee #xff
         #x11 #x22 #x33 #x44 #x55 #x66
         #x88 #xb5 #xde #xad)) ; experimental EtherType + 2 data bytes
(define capture
  (bytes-append
   (bytes #xa1 #xb2 #xc3 #xd4 0 2 0 4 0 0 0 0 0 0 0 0
          0 0 #xff #xff 0 0 0 1) ; pcap global header, Ethernet link type
   (bytes 0 0 0 1 0 0 0 0 0 0 0 16 0 0 0 16) ; record header
   frame))

(define packets (pcap-read-bytes capture))
(unless (= (length packets) 1)
  (error 'pcap-quickstart "expected one packet"))
(define pkt (car packets))
(unless (and (= (packet-timestamp pkt) 1)
             (= (packet-orig-len pkt) 16))
  (error 'pcap-quickstart "timestamp or original length mismatch"))
(define eth (decode-packet pkt))
(unless (and (equal? (ethernet-frame-src eth) "11:22:33:44:55:66")
             (= (ethernet-frame-ether-type eth) #x88b5)
             (bytes=? (ethernet-frame-payload eth) (bytes #xde #xad)))
  (error 'pcap-quickstart "Ethernet decoding mismatch"))
(displayln "pcap quickstart OK")
