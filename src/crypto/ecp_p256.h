/* crypto/ec/ecp_nistp256.c */
/*
 * Written by Adam Langley (Google) for the OpenSSL project
 */
/* Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * A 64-bit implementation of the NIST P-256 elliptic curve point multiplication
 *
 * OpenSSL integration was taken from Emilia Kasper's work in ecp_nistp224.c.
 * Otherwise based on Emilia's P224 work, which was inspired by my curve25519
 * work which got its smarts from Daniel J. Bernstein's work on the same.
 */
#include <stdint.h>
#include <string.h>

typedef __uint128_t uint128_t;
typedef __int128_t int128_t;

namespace p256
{

namespace details
{

/*-
 * The representation of field elements.
 * ------------------------------------
 *
 * We represent field elements with either four 128-bit values, eight 128-bit
 * values, or four 64-bit values. The field element represented is:
 *   v[0]*2^0 + v[1]*2^64 + v[2]*2^128 + v[3]*2^192  (mod p)
 * or:
 *   v[0]*2^0 + v[1]*2^64 + v[2]*2^128 + ... + v[8]*2^512  (mod p)
 *
 * 128-bit values are called 'limbs'. Since the limbs are spaced only 64 bits
 * apart, but are 128-bits wide, the most significant bits of each limb overlap
 * with the least significant bits of the next.
 *
 * A field element with four limbs is an 'felem'. One with eight limbs is a
 * 'longfelem'
 *
 * A field element with four, 64-bit values is called a 'smallfelem'. Small
 * values are used as intermediate values before multiplication.
 */
typedef uint128_t limb;
typedef limb felem[4];
typedef limb longfelem[4 * 2];
typedef uint64_t smallfelem[4];
}


/*
 * Encapsulate the functionality related to the elliptic curve which is useful
 * for abstracting amongst the NIST curves
 */
class traits 
{
public:
    // Type of a field element
    typedef details::smallfelem felem_type;

    // Type of a generic scalar (little endian!)
    typedef uint8_t     scalar_type[32];

    // Type of a precomputation table for generic scalar multiplication
    typedef felem_type precomp_table[17][3];

    // Size of a scalar in bytes
    static const size_t scalar_sz = 32;

    /* Convert little endian byte array to field element
     */
    static void
    scalar_to_felem(
        felem_type&         x,              // (O) Field element
        scalar_type const&  scalar          // (I) Scalar (little endian)
    );

    /* Convert field element to little endian byte array
     *
     * Requires that field element is reduced
     */
    static void
    felem_to_scalar(
        scalar_type&        scalar,         // (O) Scalar (little endian)
        felem_type const&   x               // (I) Field element
    );

    /* Scalar multiplication with respect to the base point using precomputed table
     * 
     * Output point (X, Y, Z) is stored in x_out, y_out, z_out and are reduced
     */
    static void
    scalarmult_base_impl(
        felem_type&      x_out,                  // (O) X coordinate
        felem_type&      y_out,                  // (O) Y coordinate
        felem_type&      z_out,                  // (O) Z coordinate
        const scalar_type&  g_scalar        // (I) Scalar (big endian, 28 bytes)
    );

    /*
     * Scalar multiplication with respect to an arbitrary point.
     * 
     * The small point multiples are stored in pre_comp
     *
     * Output point (X, Y, Z) is stored in x_out, y_out, z_out and are reduced
     */
    static void
    scalarmult_impl(
        felem_type&         x_out,      // (O) X coordinate
        felem_type&         y_out,      // (O) Y coordinate
        felem_type&         z_out,      // (O) Z coordinate
        const scalar_type   scalar,     // (I) Scalar (big endian, 28 bytes)
        const precomp_table pre_comp    // (I) Precomputed table
    );

    /*
     * Jacobian coordinates (X,Y,Z) - > (X/Z^2, Y/Z^3)
     *
     * Returned elements are reduced
     *
     * Returns  0  on success
     *         <>0 on failure
     */
    static int
    jacobian_to_affine(
        felem_type          x_out,  // (O) affine x coordinate
        felem_type          y_out,  // (O) affine y coordinate
        felem_type const&   x_in,   // (I) X coordinate
        felem_type const&   y_in,   // (I) Y coordinate
        felem_type const&   z_in    // (I) Z coordinate
    );

    /* Compute the table required for 'scalarmult_impl'. In this case consists of
     *
     * 0*P, 1*P, ..., 16*P
     */
    static void
    precompute_table(
        precomp_table           table,      // (O) Precompute Table
        felem_type const&       X,          // (I) X coordinate in Jacobian Coordinates
        felem_type const&       Y,          // (I) Y coordinate in Jacobian Coordinates
        felem_type const&       Z           // (I) Z coordinate in Jacobian Coordinates
    );

    /* return the field element 1 */
    static void
    one(felem_type& out);
};

namespace details
{


typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

/*
 * The underlying field. P256 operates over GF(2^256-2^224+2^192+2^96-1). We
 * can serialise an element of this field into 32 bytes. We call this an
 * felem_bytearray.
 */

typedef u8 felem_bytearray[32];

// Premultiplication table of base point
extern const smallfelem gmul[2][16][3];

/*-
 * point_double calculates 2*(x_in, y_in, z_in)
 *
 * The method is taken from:
 *   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
 *
 * Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed.
 * while x_out == y_in is not (maybe this works, but it's not tested).
 */
void
point_double(
    felem x_out,
    felem y_out,
    felem z_out,
    const felem x_in,
    const felem y_in,
    const felem z_in
);

/* get_bit returns the |i|th bit in |in| */
char
get_bit(const felem_bytearray in, int i);

/*
 * select_point selects the |idx|th point from a precomputation table and
 * copies it to out.
 */
void
select_point(
    const u64       idx,
    unsigned int    size,
    const smallfelem pre_comp[16][3],
    smallfelem      out[3]
);

/*-
 * point_add calcuates (x1, y1, z1) + (x2, y2, z2)
 *
 * The method is taken from:
 *   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl,
 * adapted for mixed addition (z2 = 1, or z2 = 0 for the point at infinity).
 *
 * This function includes a branch for checking whether the two input points
 * are equal, (while not equal to the point at infinity). This case never
 * happens during single point multiplication, so there is no timing leak for
 * ECDH or ECDSA signing.
 */
void
point_add(
    felem       x3,
    felem       y3,
    felem       z3,
    const felem x1,
    const felem y1,
    const felem z1,
    const int mixed,
    const smallfelem x2,
    const smallfelem y2,
    const smallfelem z2
);

/* smallfelem_expand converts a smallfelem to an felem */
void smallfelem_expand(felem out, const smallfelem in);

/*
 * felem_contract converts |in| to its unique, minimal representation. On
 * entry: in[i] < 2^109
 */
void felem_contract(smallfelem out, const felem in);

/*-
 * felem_is_zero returns a limb with all bits set if |in| == 0 (mod p) and 0
 * otherwise.
 * On entry:
 *   small[i] < 2^64
 */
limb smallfelem_is_zero(const smallfelem small);

/*-
 * felem_inv calculates |out| = |in|^{-1}
 *
 * Based on Fermat's Little Theorem:
 *   a^p = a (mod p)
 *   a^{p-1} = 1 (mod p)
 *   a^{p-2} = a^{-1} (mod p)
 */
void felem_inv(felem out, const felem in);

/*-
 * smallfelem_square sets |out| = |small|^2
 * On entry:
 *   small[i] < 2^64
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
void smallfelem_square(longfelem out, const smallfelem small);

/*-
 * felem_square sets |out| = |in|^2
 * On entry:
 *   in[i] < 2^109
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
void felem_square(longfelem out, const felem in);

/*-
 * felem_reduce converts a longfelem into an felem.
 * To be called directly after felem_square or felem_mul.
 * On entry:
 *   in[0] < 2^64, in[1] < 3*2^64, in[2] < 5*2^64, in[3] < 7*2^64
 *   in[4] < 7*2^64, in[5] < 5*2^64, in[6] < 3*2^64, in[7] < 2*64
 * On exit:
 *   out[i] < 2^101
 */
void felem_reduce(felem out, const longfelem in);

/*-
 * felem_mul sets |out| = |in1| * |in2|
 * On entry:
 *   in1[i] < 2^109
 *   in2[i] < 2^109
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
void felem_mul(longfelem out, const felem in1, const felem in2);

/*-
 * felem_shrink converts an felem into a smallfelem. The result isn't quite
 * minimal as the value may be greater than p.
 *
 * On entry:
 *   in[i] < 2^109
 * On exit:
 *   out[i] < 2^64
 */
void felem_shrink(smallfelem out, const felem in);

void smallfelem_zero(smallfelem out);
void smallfelem_one(smallfelem out);
void smallfelem_assign(smallfelem out, const smallfelem in);

/*-
 * smallfelem_neg sets |out| to |-small|
 * On exit:
 *   out[i] < out[i] + 2^105
 */
void smallfelem_neg(felem out, const smallfelem small);

/*
 * point_add_small is the same as point_add, except that it operates on
 * smallfelems
 */
void point_add_small(smallfelem x3, smallfelem y3, smallfelem z3,
                            smallfelem x1, smallfelem y1, smallfelem z1,
                            smallfelem x2, smallfelem y2, smallfelem z2);

void
point_double_small(smallfelem x_out, smallfelem y_out, smallfelem z_out,
                   const smallfelem x_in, const smallfelem y_in,
                   const smallfelem z_in);

/* copy_small_conditional copies in to out iff mask is all ones. */
void copy_small_conditional(felem out, const smallfelem in, limb mask);
}

}