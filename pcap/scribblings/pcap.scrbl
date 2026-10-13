#lang scribble/manual

@(require (for-label pcap
                     racket/base
                     racket/contract)
           scribble/example)

@title{pcap: reading and dissecting classic pcap capture files}
@defmodule[pcap]

The @racket[pcap] package reads capture files in the @deftech{classic pcap}
format---the file format written by @hyperlink["https://www.tcpdump.org/"]{libpcap}
and @hyperlink["https://www.tcpdump.org/"]{tcpdump}, as specified by the
@hyperlink["https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap"]{@tt{draft-ietf-opsawg-pcap}}
Internet draft and described on the
@hyperlink["https://wiki.wireshark.org/Development/LibpcapFileFormat"]{Wireshark wiki}.
It is implemented in pure Racket: no FFI and no system dependencies.
On top of raw packet data it offers dissection of Ethernet II (including
802.1Q and 802.1ad VLAN tags), IPv4, IPv6 (fixed header only), TCP, and UDP.

@;{------------ scope ------------}
@section[#:tag "scope"]{Scope}

@itemlist[
 @item{All four classic magic-number variants are supported, covering both
   byte orders and both timestamp resolutions:
   @itemlist[
     @item{@tt{a1 b2 c3 d4} --- big-endian, microseconds}
     @item{@tt{d4 c3 b2 a1} --- little-endian, microseconds}
     @item{@tt{a1 b2 3c 4d} --- big-endian, nanoseconds}
     @item{@tt{4d 3c b2 a1} --- little-endian, nanoseconds}]}
 @item{@deftech{pcapng} files are @bold{not} supported.  Feeding a pcapng file
   to any reader in this package raises @racket[exn:fail] with a
   ``bad magic number'' message.}
 @item{Checksums are not validated.  IPv6 extension headers are not parsed:
   @racket[decode-ipv6] exposes only the fixed 40-octet header.}]

@;{------------ reading ------------}
@section[#:tag "reading"]{Reading captures}

@defstruct[pcap-header ([link-type exact-nonnegative-integer?]
                        [snaplen exact-nonnegative-integer?])]{
  File-level information.  @racket[link-type] is the capture's link-layer
  header type (the pcap @tt{LINKTYPE_} number; Ethernet is @racket[1]),
  normalized to the low 16 bits of the field as the format's reserved
  upper bits allow.  @racket[snaplen] is the snapshot length declared by
  the writer.}

@defstruct[packet ([timestamp rational?]
                   [link-type exact-nonnegative-integer?]
                   [data bytes?]
                   [orig-len exact-nonnegative-integer?])]{
  One captured packet.  @racket[timestamp] is an @emph{exact rational}
  number of seconds since the UNIX epoch, combining the record's seconds
  and fractional fields; the fractional field is interpreted as
  microseconds or nanoseconds according to the file's magic number.
  @racket[link-type] repeats the capture's link type for convenience.
  @racket[data] holds exactly the captured octets, i.e. @tt{incl_len}
  bytes.  @racket[orig-len] is the packet's original wire length
  (@tt{orig_len}), which is larger than the data length when the capture
  truncated packets to the snapshot length.}

@defproc[(pcap-read [in input-port?]) (listof packet?)]{
  Reads every packet record from @racket[in] and returns them in capture
  order.  Raises @racket[exn:fail] if the global header is missing or
  truncated, the magic number is unrecognized, or a packet record or its
  data is truncated.}

@defproc[(pcap-read-file [path path-string?]) (listof packet?)]{
  Opens the file at @racket[path] and reads it with @racket[pcap-read].}

@defproc[(pcap-read-bytes [bs bytes?]) (listof packet?)]{
  Reads a capture held in memory as @racket[bs].}

@defproc[(pcap-read-header [in input-port?]) pcap-header?]{
  Reads and validates just the 24-octet global header (consuming it from
  @racket[in]), without reading packet records.  Useful for inspecting a
  capture's link type before committing to a full read.}

@;{------------ dissection ------------}
@section[#:tag "dissection"]{Dissection}

@defstruct[ethernet-frame ([dst string?]
                           [src string?]
                           [ether-type exact-nonnegative-integer?]
                           [payload (or/c bytes? ipv4-header? ipv6-header?
                                          tcp-header? udp-header?)]
                           [tagged? boolean?])]{
  A decoded Ethernet II frame.  @racket[dst] and @racket[src] are MAC
  addresses formatted @tt{"aa:bb:cc:dd:ee:ff"}.  802.1Q, 802.1ad, and the
  legacy @tt{0x9100} VLAN tags (including QinQ stacks) are skipped:
  @racket[ether-type] reports the final inner EtherType and @racket[tagged?]
  reports whether any VLAN tag was present.}

@defstruct[ipv4-header ([src string?]
                        [dst string?]
                        [protocol exact-nonnegative-integer?]
                        [ttl exact-nonnegative-integer?]
                        [options bytes?]
                        [payload (or/c bytes? tcp-header? udp-header?)])]{
  A decoded IPv4 packet.  @racket[src] and @racket[dst] are dotted-quad
  strings.  @racket[options] holds the bytes between the minimum 20-octet
  header and the length given by the IHL field (empty for IHL 5).  The
  payload is trimmed to the IP total-length field, which discards Ethernet
  padding on small frames; a capture truncated below the declared total
  length yields the remaining bytes.}

@defstruct[ipv6-header ([src string?]
                        [dst string?]
                        [next-header exact-nonnegative-integer?]
                        [hop-limit exact-nonnegative-integer?]
                        [payload (or/c bytes? tcp-header? udp-header?)])]{
  A decoded IPv6 fixed header.  Addresses are formatted per RFC 5952
  (lowercase hex with the longest zero run compressed to @tt{"::"}, e.g.
  @tt{"2001:db8::1"}).  Extension headers are not parsed:
  @racket[next-header] is the raw protocol number and @racket[payload] is
  everything past the fixed 40-octet header.}

@defstruct[tcp-header ([src-port exact-nonnegative-integer?]
                       [dst-port exact-nonnegative-integer?]
                       [seq exact-nonnegative-integer?]
                       [ack exact-nonnegative-integer?]
                       [flags exact-nonnegative-integer?]
                        [payload (or/c bytes? tcp-header? udp-header?)])]{
  A decoded TCP segment.  @racket[flags] packs the nine meaningful flag
  bits (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN), e.g.
  @racket[#x02] is SYN and @racket[#x18] is PSH+ACK.}

@defstruct[udp-header ([src-port exact-nonnegative-integer?]
                       [dst-port exact-nonnegative-integer?]
                       [payload (or/c bytes? tcp-header? udp-header?)])]{
  A decoded UDP datagram, with the payload trimmed to the UDP length
  field.}

@defproc[(decode-ethernet [bs bytes?]) ethernet-frame?]{
  Decodes one Ethernet II frame, skipping any VLAN tags.}

@defproc[(decode-ipv4 [bs bytes?]) ipv4-header?]{
  Decodes one IPv4 header and its payload.}

@defproc[(decode-ipv6 [bs bytes?]) ipv6-header?]{
  Decodes one IPv6 fixed header and its payload.}

@defproc[(decode-tcp [bs bytes?]) tcp-header?]{
  Decodes one TCP header and its payload.}

@defproc[(decode-udp [bs bytes?]) udp-header?]{
  Decodes one UDP header and its payload.  Each raises @racket[exn:fail] when the
  input is shorter than the corresponding minimum header or carries a
  malformed length or version field.  For example:

  @examples[
    (require pcap)
    (define eth
      (decode-ethernet (bytes #xaa #xbb #xcc #xdd #xee #xff
                              #x11 #x22 #x33 #x44 #x55 #x66
                              #x08 #x00 #xde #xad)))
    (ethernet-frame-dst eth)
    (ethernet-frame-ether-type eth)
    (ethernet-frame-tagged? eth)
    (ethernet-frame-payload eth)]}

@defproc[(decode-packet [pkt packet?]) ethernet-frame?]{
  Convenience: dissects a packet from an Ethernet capture into a nested
  structure.  The result is an @racket[ethernet-frame] whose payload is an
  @racket[ipv4-header] or @racket[ipv6-header] when the EtherType says so,
  whose payload in turn is a @racket[tcp-header] or @racket[udp-header]
  when the protocol/next-header field says so, and raw bytes otherwise.
  If a transport header is truncated or malformed it is left undecoded
  rather than raising.  Use the layer predicates (@racket[ipv4-header?],
  @racket[tcp-header?], ...) to navigate the nesting.}

@;{------------ errors ------------}
@section[#:tag "errors"]{Errors and limitations}

All failures raise @racket[exn:fail] with descriptive messages:
truncated global header, bad magic number (the message notes that pcapng
is unsupported), truncated packet record header, and truncated packet
data.  A record whose captured length exceeds a 16 MiB safety limit is
rejected as probably corrupt so that garbage length fields cannot trigger
huge allocations.

Limitations: checksums are never validated; IPv6 extension headers,
IP fragmentation, and TCP stream reassembly are out of scope; only
Ethernet-captured packets are accepted by @racket[decode-packet].
