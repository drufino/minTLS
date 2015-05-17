/* Public interface to RSA encryption and signature primitives
 * 
 * [1] https://tools.ietf.org/html/rfc3447
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
 
#include "rsa.h"
#include <cstring>
#include "core/bigint.hpp"
#include <iostream>
#include <core/portability.h>
#include <asn1/asn1_archive.hpp>
 
extern "C" {

int
asn1_digest(
    MinTLS_Hash     hash,    // (I) Hash scheme
    uint8_t const** asn1,    // (O) ASN.1 digest
    size_t *        asn1_len // (O) ASN.1 digest length
)
{
    // RFC-3447 Appendix 2.4
    static uint8_t asn1_sha1[]   = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    static uint8_t asn1_sha224[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    static uint8_t asn1_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static uint8_t asn1_sha384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static uint8_t asn1_sha512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

    switch (hash)
    {
    #define P(x) { *asn1 = x; *asn1_len = sizeof(x); break; }
    case MinTLS_SHA_160: P(asn1_sha1);
    case MinTLS_SHA_224: P(asn1_sha224);
    case MinTLS_SHA_256: P(asn1_sha256);
    case MinTLS_SHA_384: P(asn1_sha384);
    case MinTLS_SHA_512: P(asn1_sha512);
    default: *asn1 = 0; asn1_len = 0; return -1;
    #undef P
    }
    return 0;
}

// RFC-3447 Section 9.2
int
mintls_pkcs1_v15_encode(
    uint8_t *       emsg,   // (O) Encoded Message
    size_t const    emlen,  // (I) Target length
    MinTLS_Hash     hash,   // (I) Hash scheme
    uint8_t const * msg,    // (I) Message
    size_t const    msg_len // (I) Message length
)
{

    // 0x00 | 0x01 | PS | 0x00 | asn1 | tag 

    uint8_t const * asn1 = {0x0};
    size_t          asn1_len(0);
    if (0 != asn1_digest(
            hash,       // (I) Hash scheme
            &asn1,      // (O) ASN.1 digest
            &asn1_len   // (O) ASN.1 digest length
        ))
    {
        return -1;
    }

    if (emlen < 11 + asn1_len + mintls_hash_tag_length(hash))
    {
        return -1;
    }

    uint8_t *p = emsg;

    *p++ = '\x00';
    *p++ = '\x01';

    size_t const ps_len = emlen - 3 - asn1_len - mintls_hash_tag_length(hash);

    memset(p, '\xff', ps_len);
    p += ps_len;

    *p++ = '\x00';


    memcpy(p, asn1, asn1_len);
    p += asn1_len;

    p +=
    mintls_hash(
        hash,       // (I) SHA Variant
        msg,        // (I) Input
        msg_len,    // (I) Size of input
        p           // (O) Tag
    );

    if (p - emsg != emlen)
    {
        return -1;
    }

    return 0;
}

int
mintls_rsa_sign(
    uint8_t *       sig,    // (O) Signature
    MinTLS_RSASignMethod   method, // (I) Method
    MinTLS_Hash     hash,   // (I) Hash scheme
    uint8_t const * msg,    // (I) Message
    size_t const    msg_len,// (I) Message length (bytes)
    uint8_t const * n_,     // (I) Modulus
    size_t const    n_len,  // (I) Modulus length
    uint8_t const * d_,     // (I) Exponent
    size_t const    d_len   // (I) Exponent length
)
{
    if (method != MinTLS_RSASSA_PKCS1_V1_5)
    {
        return -1;
    }

    // Encode the message according to PKCS #1 V1.5 (RFC-3447 Section 9.2)
	VLA(uint8_t, encoded_msg, n_len);
    if (method == MinTLS_RSASSA_PKCS1_V1_5)
    {
        if (mintls_pkcs1_v15_encode(encoded_msg, n_len, hash, msg, msg_len) != 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    // Construct integer representation of encoded message
	BigInt m(encoded_msg, n_len);

    // Construct integer representation of the key
    BigInt n(n_, n_len);
    BigInt d(d_, d_len);

    // Signature primitive
    BigInt s = BigInt::exp_mod(m,d,n);

    s.write_binary(sig,n.size());

    return 0;
}

int
mintls_rsa_verify(
    uint8_t const * sig,    // (I) Signature (must be same size as modulus)
    MinTLS_RSASignMethod   method, // (I) Method
    MinTLS_Hash     hash,   // (I) Hash scheme
    uint8_t const * msg,    // (I) Message
    size_t const    msg_len,// (I) Message length
    uint8_t const * n_,     // (I) Modulus
    size_t const    n_len,  // (I) Modulus length
    uint8_t const * e_,     // (I) Public exponent
    size_t const    e_len   // (I) Public exponent
)
{
    BigInt s(sig, n_len);
    BigInt n(n_, n_len);
    BigInt e(e_, e_len);

    return mintls_rsa_verify(
        s,       // (I) Signature
        method,  // (I) Method
        hash,    // (I) Hash scheme
        msg,     // (I) Message
        msg_len, // (I) Message Length
        n,       // (I) Modulus
        e        // (I) Public exponent
    );
}

}

int
mintls_rsa_verify(
    BigInt const&              s,       // (I) Signature
    MinTLS_RSASignMethod       method,  // (I) Method
    MinTLS_Hash                hash,    // (I) Hash scheme
    uint8_t const *            msg,     // (I) Message
    size_t const               msg_len, // (I) Message Length
    BigInt const&              n,       // (I) Modulus
    BigInt const&              e        // (I) Public exponent
)
{
    BigInt m = BigInt::exp_mod(s,e,n);

    VLA(uint8_t, encoded_msg, n.size());
    m.write_binary(&encoded_msg[0], n.size());
    VLA(uint8_t, encoded_msg2, n.size());
    if (method == MinTLS_RSASSA_PKCS1_V1_5)
    {
        if (mintls_pkcs1_v15_encode(&encoded_msg2[0], n.size(), hash, msg, msg_len) != 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    // XXX - add safe compare
    if (!memcmp(encoded_msg, encoded_msg2, n.size()))
    {
        return 0;
    }
    else
    {
        return -1;
    }
}



template<typename T>
mintls_error
mintls_rsa_decode_public_key_impl(
    uint8_t const *   pubkey, // (I) Encoded public key
    size_t const      pk_len, // (I) Encoded length
    T&                n,      // (O) Modulus
    T&                e       // (O) Exponent
)
{
    using namespace asn1;

    iarchive iar(pubkey, pk_len);
    asn1::ber_archive ar(iar, "PubKeyVerify");

    try {
        ar & start_cons() & INTEGER & n & INTEGER & e & end_cons();
    }
    catch (std::exception const& e)
    {
        tf_dbg("[E] tls_verify: signature public_key " << e.what())
        return mintls_err_decode_error;
    }

    if (iar.left() > 0)
    {
        tf_debug("[E] tls_verify: signature public key not exhausted");
        return mintls_err_decode_error;
    }

    return mintls_success;
}

mintls_error
mintls_rsa_decode_public_key(
    uint8_t const *             pubkey, // (I) Encoded public key
    size_t const                pk_len, // (I) Encoded length
    BigInt&                     n,      // (O) Modulus
    BigInt&                     e       // (O) Exponent
)
{
    return mintls_rsa_decode_public_key_impl<BigInt>(pubkey, pk_len, n, e);
}

mintls_error
mintls_rsa_decode_public_key(
    uint8_t const *             pubkey, // (I) Encoded public key
    size_t const                pk_len, // (I) Encoded length
    std::vector<uint8_t>&       n,      // (O) Modulus
    std::vector<uint8_t>&       e       // (O) Exponent
)
{
    return mintls_rsa_decode_public_key_impl<std::vector<uint8_t> >(pubkey, pk_len, n, e);
}
