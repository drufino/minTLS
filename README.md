minTLS
=========
Copyright David Rufino (c), 2015. See LICENSE for details.

This library is a BSD-licensed, minimal implementation of TLS 1.2. It is largely written in C++ but designed to be used through the pure C API, so that it may be used in any language with a C FFI. **Although ultimately the intention is to have a solid production ready TLS implementation, currently it is alpha quality and incomplete in many areas, so should only be used for testing purposes.**

The focus is on implementing the TLS protocol correctly and securely, rather than on the underlying cryptographic primitives, as these are generally well studied and tested. To give context, there have been a number of notable pure implementation bugs, with catastrophic consequences

  * [Goto Fail](https://www.imperialviolet.org/2014/02/22/applebug.html)     Accidentally skips chain of trust verification


  * [Heartbleed](http://en.wikipedia.org/wiki/Heartbleed)           Server responds to specially crafted TLS message by dumping the contents of memory


  * [Early CCS](https://www.imperialviolet.org/2014/06/05/earlyccs.html) Server incorrectly accepts out of order handshake messages, ultimately allowing man-in-the-middle attack


I make a few design decisions to hopefully avoid some pitfalls in implementing the TLS protocol

  * Rigorous unit testing and integration testing
  * Create high-level frameworks for dealing with 
    * TLS State machine
    * X.509/ASN.1 BER Decoding
    * TLS Record decoding and encoding
  * Implement key functionality in 'pure' functions or classes with immutable state, to simplify testing and understanding of the code. In particular avoid complex design patterns.

In short we attempt to separate the low-level memory management and serialization from the high-level protocol logic. This ought to make it easier to spot bugs, audit and test.

This project makes use of the following contributions

  - Base64, BigInt and SHA routines from XySSL 0.9
  - ECDH P-256 and P-224 from OpenSSL
  - Reference AES implementation

