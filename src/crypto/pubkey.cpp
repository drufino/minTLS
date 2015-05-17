/*
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "pubkey.h"
#include "rsa.h"
#include "hash.h"
#include <string.h>
#include <asn1/asn1.hpp>
#include <asn1/asn1_archive.hpp>
#include <core/tf_debug.hpp>

extern "C" {

MinTLS_SignatureAlgorithm mintls_pubkey_algo(char const *oid)
{
    // http://tools.ietf.org/html/rfc5698 Sec 8.
    if (!strcmp(oid,"1.2.840.113549.1.1.1") || // rsaEncryption
        !strcmp(oid,"1.2.840.113549.1.1.5") || // sha1WithRSAEncryption
        !strcmp(oid,"1.2.840.113549.1.1.11")|| // sha256WithRSAEncryption
        !strcmp(oid,"1.2.840.113549.1.1.12")|| // sha384WithRSAEncryption
        !strcmp(oid,"1.2.840.113549.1.1.13"))  // sha512WithRSAEncryption
    {
        return MinTLS_RSA_PKCS15;
    }
    else
    {
        return MinTLS_Anonymous;
    }
}


MinTLS_Hash mintls_pubkey_algo_hash(char const *oid)
{
    // http://tools.ietf.org/html/rfc5698 Sec 8.
    if (!strcmp(oid,"1.2.840.113549.1.1.1")) // rsaEncryption
    {
        return (MinTLS_Hash)0;
    }
    else if (!strcmp(oid,"1.2.840.113549.1.1.5"))// sha1WithRSAEncryption
    {
        return MinTLS_SHA_160;
    }
    else if (!strcmp(oid,"1.2.840.113549.1.1.11")) // sha256WithRSAEncryption
    {
        return MinTLS_SHA_256;
    }
    else if (!strcmp(oid,"1.2.840.113549.1.1.12")) // sha384WithRSAEncryption
    {
        return MinTLS_SHA_384;
    }
    else if (!strcmp(oid,"1.2.840.113549.1.1.13"))  // sha512WithRSAEncryption
    {
        return MinTLS_SHA_512;
    }
    else
    {
        return (MinTLS_Hash)0;
    }
}

/* Public key signature verification
 *
 * Return -1 on error
 *         0 otherwise
 */
mintls_error
mintls_pubkey_verify(
    uint8_t const *         sig,        // (I) Signature
    size_t const            sig_len,    // (I) Signature length
    MinTLS_SignatureAlgorithm algo,     // (I) Signature Algorithm
    MinTLS_Hash             hash,       // (I) Hash Algorithm
    uint8_t const *         msg,        // (I) Message
    size_t const            msg_len,    // (I) Message length (bytes)
    uint8_t const *         pubkey,     // (I) Public Key (Usually ASN.1 Encoded)
    size_t const            pubkey_len  // (I) Public Key Length
)
{
    if (algo != MinTLS_RSA_PKCS15)
    {
        return mintls_err_unsupported_certificate;
    }

    // Public key
    BigInt n, e;

    // Unpack the public key
    mintls_error err = 
    mintls_rsa_decode_public_key(pubkey, pubkey_len, n, e);

    if (err != mintls_success)
    {
        return err;
    }
 
    // Check signature has correct size
    if (n.size() != sig_len)
    {
        tf_debug("[E] Signature had size %d but modulus was length %d", sig_len, n.size());
        return mintls_err_decode_error;
    }

    BigInt s(sig, sig_len);

    // Do the verification process
    int res=
    mintls_rsa_verify(
        s,              // (I) Signature (must be same size as modulus)
        MinTLS_RSASSA_PKCS1_V1_5, // (I) Method
        hash,           // (I) Hash scheme
        msg,            // (I) Message
        msg_len,        // (I) Message length
        n,              // (I) Modulus
        e               // (I) Public exponent
    );
    if (res == 0)
    {
        return mintls_success;
    }
    else
    {
        return mintls_err_bad_record_mac;
    }
}

}
