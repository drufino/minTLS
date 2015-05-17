/* Public interfae to public key algorithms
 *
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_pubkey_h
#define mintls_pubkey_h
#include <stdint.h>
#include <stdlib.h>
#include "hash.h"
#include "tls_api.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    // Missing
    MinTLS_Anonymous=0,
    // RFC-3447
    MinTLS_RSA_PKCS15=1
} MinTLS_SignatureAlgorithm;

/* Convert from IANA ID to signature algorithm
 *
 * http://tools.ietf.org/html/rfc5698 Sec 8.
 */
MinTLS_SignatureAlgorithm mintls_pubkey_algo(char const *oid);

/* Convert IANA ID to public key algorithm
 *
 * Returns 0 if OID not recognised
 */
MinTLS_Hash     mintls_pubkey_algo_hash(char const *oid);

/* Public key verification
 *
 * Return mintls_success            on success
 *        mintls_err_decode_error   in case the public key is malformed or sig_len isnt equal to modulus size
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
);


#ifdef __cplusplus
} // extern "C"

#endif

#endif /* TF_PUBKEY_H */
