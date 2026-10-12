#lang info

(define collection 'multi)
(define version "0.1")
(define deps '("base" "rackunit-lib"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib"))
(define pkg-desc "Pure-Racket reader for classic pcap capture files with Ethernet, IPv4/IPv6, TCP, and UDP dissection.")
(define pkg-authors '("turinglambdaai"))
(define license 'MIT)
(define test-omit-paths '("pcap/scribblings"))
