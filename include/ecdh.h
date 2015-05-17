/* Functionality related to Elliptic Curve Diffie-Hellman in TLS
 * 
 * Primary reference
 *   [1] Guide To Elliptic Curve Cryptography
 *   [2] RFC 4492 - ECC Cipher Suites for TLS
            https://tools.ietf.org/html/rfc4492
 *   [3] NIST Recommendations for elliptic curves
 *          http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
 *   [4] IEEE, "Standard Specifications for Public Key Cryptography", IEEE 1363
 *   [5] ANSI, "Public Key Cryptography For The Financial Services
 *       Industry: The Elliptic Curve Digital Signature Algorithm
 *       (ECDSA)", ANSI X9.62, 1998.
 * 
 * The basic algorithm is defined in [4] Section 9.2 (DL/ECKAS-DH1)
 * Encoding schemes are defined in [5] Section 4.3
 * Implementations taken from OpenSSL
 * 
 * Consider only weierstrass form
 * 
 *    y^2 = x^3 + ax + b (mod p)
 * 
 * The base point G is a generator of the maximal subgroup of E(F_p) of (prime) order r.
 * Private keys are elements of F_r.
 * The corresponding public key is sG = P = (P_x,P_y)
 * The shared secret is the x-coordinate of s(s'G) = s'(sG).
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_ecdh_h
#define mintls_ecdh_h
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    mintls_secp224r1=21,
    mintls_secp256r1=23
} MinTLS_NamedCurve;

/* Return size of scalar/private key
 */
size_t mintls_ecdh_scalar_size(MinTLS_NamedCurve curve);

/* Return size of point/public key
 *
 * Encoding is in uncompressed form [5] Section 4.3.6
 */
size_t mintls_ecdh_point_size(MinTLS_NamedCurve curve);

/* Calculate scalar multiple of base point
 *
 * Returns:   0 on success
 *          <>0 on failure
 */
int
mintls_ecdh_base_scalar_mult(
    MinTLS_NamedCurve   curve,          // (I) Curve
    uint8_t const *     scalar,         // (I) Scalar (big endian using [5] 4.3.3)
    size_t const        scalar_sz,      // (I) Size of the scalar
    uint8_t *           point           // (O) Point (uncompressed using [5] 4.3.6)
);

/* Calculate scalar multiple of arbitrary point
 *
 * Returns:   0 on success
 *          <>0 on failure 
 */
int
mintls_ecdh_scalar_mult(
    MinTLS_NamedCurve   curve,   // (I) Curve
    uint8_t const *     scalar,         // (I) Scalar (big endian using [5] 4.3.3)
    size_t const        scalar_sz,      // (I) Scalar size
    uint8_t const *     base_point,     // (I) Base point (uncompressed using [5] 4.3.6)
    size_t const        base_point_sz,  // (I) Base point size
    uint8_t *           point           // (O) Point (uncompressed using [5] 4.3.6)
);

#ifdef __cplusplus
}
#endif

#endif /* mintls_ecdh_h  */