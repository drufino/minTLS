/* Public interface to RSA encryption and signature primitives
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_rsa_h
#define mintls_rsa_h
#include <stdlib.h>
#include <stdint.h>
#include "hash.h"
#include "tls_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MinTLS_RSA_RAW=0,          // RFC-3447 without message encoding
    MinTLS_RSASSA_PKCS1_V1_5=1 // RFC-3447
} MinTLS_RSASignMethod;

/* Implement PKCS #1 1.5 encoding scheme
 *
 * Return -1 if emlen is too small or hash is unsupported
 *         0 otherwise
 */
int
mintls_pkcs1_v15_encode(
    uint8_t *       emsg,   // (O) Encoded Message
    size_t const    emlen,  // (I) Target message length
    MinTLS_Hash     hash,   // (I) Hash scheme
    uint8_t const * msg,    // (I) Message
    size_t const    msg_len // (I) Message length
);

/* Implement RSA signature according to RFC-3447 Section 8
 *
 * Return -1 on error
 *         0 otherwise
 */
int
mintls_rsa_sign(
    uint8_t *       sig,    // (O) Signature (must be same size as modulus)
    MinTLS_RSASignMethod method, // (I) Method
    MinTLS_Hash     hash,   // (I) Hash scheme
    uint8_t const * msg,    // (I) Message
    size_t const    msg_len,// (I) Message length (bytes)
    uint8_t const * n,      // (I) Modulus
    size_t const    n_len,  // (I) Modulus length
    uint8_t const * d,      // (I) Private Exponent
    size_t const    d_len   // (I) Private Exponent length
);

/* Implement RSA signature verification according to RFC-3447 Section 8
 *
 * Return  0 if signature is valid
 *        -1 otherwise
 */
int
mintls_rsa_verify(
    uint8_t const * sig,    // (I) Signature (must be same size as modulus)
    MinTLS_RSASignMethod method, // (I) Method
    MinTLS_Hash     hash,   // (I) Hash scheme
    uint8_t const * msg,    // (I) Message
    size_t const    msg_len,// (I) Message length
    uint8_t const * n,      // (I) Modulus
    size_t const    n_len,  // (I) Modulus length
    uint8_t const * e,      // (I) Public exponent
    size_t const    e_len   // (I) Public exponent
);

#ifdef __cplusplus
}

#include <vector>

// Forward declaration
class BigInt;

/* Implement RSA signature verification according to RFC-3447 Section 8
 *
 * Return  0 if signature is valid
 *        -1 otherwise
 */
int
mintls_rsa_verify(
    BigInt const&              s,       // (I) Signature
    MinTLS_RSASignMethod       method,  // (I) Method
    MinTLS_Hash                hash,    // (I) Hash scheme
    uint8_t const *            msg,     // (I) Message
    size_t const               msg_len, // (I) Message Length
    BigInt const&              n,       // (I) Modulus
    BigInt const&              e        // (I) Public exponent
);

/* Extract RSA modulus and exponent from ASN.1 encoded sequence
 *
 * Return mintls_success          if valid encoding
 *        mintls_err_decode_error otherwise
 */
mintls_error
mintls_rsa_decode_public_key(
    uint8_t const *             pubkey, // (I) Encoded public key
    size_t const                pk_len, // (I) Encoded length
    BigInt&                     n,      // (O) Modulus
    BigInt&                     e       // (O) Exponent
);

/* Extract RSA modulus and exponent from ASN.1 encoded sequence
 *
 * Return mintls_success          if valid encoding
 *        mintls_err_decode_error otherwise
 */
mintls_error
mintls_rsa_decode_public_key(
    uint8_t const *             pubkey, // (I) Encoded public key
    size_t const                pk_len, // (I) Encoded length
    std::vector<uint8_t>&       n,      // (O) Modulus
    std::vector<uint8_t>&       e       // (O) Exponent
);

#endif

#endif /* tf_rsa_h */
