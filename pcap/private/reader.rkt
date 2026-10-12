#lang racket/base

;; Reader for classic pcap capture files (the libpcap/tcpdump format),
;; as specified by draft-ietf-opsawg-pcap and described at
;; <https://wiki.wireshark.org/Development/LibpcapFileFormat>.
;;
;; All four magic-number variants are supported:
;;
;;   #xa1b2c3d4   big-endian     microseconds
;;   #xd4c3b2a1   little-endian   microseconds
;;   #xa1b23c4d   big-endian     nanoseconds
;;   #x4d3cb2a1   little-endian   nanoseconds
;;
;; pcapng files are explicitly out of scope; they are rejected with a
;; bad-magic-number error (the message points this out, since a pcapng
;; file is the most likely thing a user feeds here by mistake).

(require racket/bytes
         racket/contract)

;; ---- data structures -------------------------------------------------

(struct pcap-header (link-type snaplen) #:transparent)
(struct packet (timestamp link-type data orig-len) #:transparent)

(provide
 (contract-out
  (struct pcap-header
    ((link-type exact-nonnegative-integer?)
     (snaplen exact-nonnegative-integer?)))
  (struct packet
    ((timestamp rational?)
     (link-type exact-nonnegative-integer?)
     (data bytes?)
     (orig-len exact-nonnegative-integer?)))
  (pcap-read (-> input-port? (listof packet?)))
  (pcap-read-file (-> path-string? (listof packet?)))
  (pcap-read-bytes (-> bytes? (listof packet?)))
  (pcap-read-header (-> input-port? pcap-header?))))

;; ---- format constants -----------------------------------------------

;; The global header is 24 octets and each packet record header is 16
;; octets; packet data is not padded.
(define global-header-size 24)
(define record-header-size 16)

;; Magic number (interpreted as a big-endian 32-bit integer over the
;; first four octets on disk) -> (cons big-endian? nanosecond?).
(define magic-table
  (list (cons #xa1b2c3d4 (cons #t #f))
        (cons #xa1b23c4d (cons #t #t))
        (cons #xd4c3b2a1 (cons #f #f))
        (cons #x4d3cb2a1 (cons #f #t))))

;; Safety limit against corrupt files that claim absurd record lengths;
;; libpcap's MAXIMUM_SNAPLEN is 256 KiB, far below this.
(define max-incl-len (* 16 1024 1024))

;; ---- byte helpers ----------------------------------------------------

(define (read-exactly in n what)
  (define bs (read-bytes n in))
  (define got (if (eof-object? bs) 0 (bytes-length bs)))
  (unless (= got n)
    (error 'pcap-read "truncated ~a: expected ~a bytes, found ~a" what n got))
  bs)

(define (u16 bs big-endian? [off 0])
  (integer-bytes->integer bs #f big-endian? off (+ off 2)))

(define (u32 bs big-endian? [off 0])
  (integer-bytes->integer bs #f big-endian? off (+ off 4)))

;; ---- global header ---------------------------------------------------

;; Reads the 24-octet global header from `in` (consuming it) and
;; returns three values: a pcap-header, big-endian?, and nanosecond?.
(define (read-global-header in)
  (define bs (read-exactly in global-header-size "global header"))
  (define raw-magic (integer-bytes->integer bs #f #t 0 4))
  (define info (assoc raw-magic magic-table))
  (unless info
    (error 'pcap-read
           (string-append
            "bad magic number #x~a: not a classic pcap file"
            " (expected #xa1b2c3d4, #xd4c3b2a1, #xa1b23c4d, or #x4d3cb2a1);"
            " pcapng files are not supported by this package")
           (string-upcase (number->string raw-magic 16))))
  (define big-endian? (car (cdr info)))
  (define nanosecond? (cdr (cdr info)))
  ;; version-major/minor, thiszone and sigfigs are read but ignored,
  ;; matching libpcap's lenient behavior.
  (void (u16 bs big-endian? 4)   ; version-major
        (u16 bs big-endian? 6)   ; version-minor
        (u32 bs big-endian? 8)   ; thiszone  (reserved; MUST be ignored)
        (u32 bs big-endian? 12)) ; sigfigs   (reserved; MUST be ignored)
  (define snaplen (u32 bs big-endian? 16))
  ;; The last field occupies 4 octets but only the low 16 bits carry
  ;; the link type; the upper bits are reserved (FCS length and flags).
  (define link-type (bitwise-and (u32 bs big-endian? 20) #xffff))
  (values (pcap-header link-type snaplen) big-endian? nanosecond?))

;; ---- public API ------------------------------------------------------

;; Returns the file-level header of the capture without reading any
;; packet records.
(define (pcap-read-header in)
  (define-values (header _big-endian? _nanosecond?) (read-global-header in))
  header)

;; Reads every packet record from `in` and returns them in capture
;; order.  Timestamps are exact rational seconds; the fractional part
;; is microseconds or nanoseconds depending on the file's magic number.
(define (pcap-read in)
  (define-values (header big-endian? nanosecond?) (read-global-header in))
  (define link-type (pcap-header-link-type header))
  (define ts-scale (if nanosecond? 1000000000 1000000))
  (define (read-u32 bs off) (u32 bs big-endian? off))
  (let loop ((offset global-header-size) (acc '()))
    (cond
      ((eof-object? (peek-byte in)) (reverse acc))
      (else
       (define rh
         (read-exactly in record-header-size
                       (format "packet record header at offset ~a" offset)))
       (define ts-sec (read-u32 rh 0))
       (define ts-frac (read-u32 rh 4))
       (define incl-len (read-u32 rh 8))
       (define orig-len (read-u32 rh 12))
       (unless (<= incl-len max-incl-len)
         (error 'pcap-read
                (string-append
                 "implausibly large packet record at offset ~a:"
                 " captured length ~a exceeds the safety limit of ~a bytes;"
                 " the file is probably corrupt")
                offset incl-len max-incl-len))
       (define data
         (read-exactly in incl-len
                       (format "packet data at offset ~a (captured length ~a)"
                               (+ offset record-header-size) incl-len)))
       ;; orig_len SHOULD NOT be less than incl_len; if a writer gets
       ;; this wrong, normalize upward as the draft permits.
       (loop (+ offset record-header-size incl-len)
             (cons (packet (+ ts-sec (/ ts-frac ts-scale))
                           link-type
                           data
                           (max orig-len incl-len))
                   acc))))))

(define (pcap-read-file path)
  (call-with-input-file path pcap-read))

(define (pcap-read-bytes bs)
  (pcap-read (open-input-bytes bs)))
