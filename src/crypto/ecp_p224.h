/* Implementation of P-224 due to Emilia Kasper (Google)
 */
/*
 * Written by Emilia Kasper (Google) for the OpenSSL project.
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
 * A 64-bit implementation of the NIST P-224 elliptic curve point multiplication
 *
 * Inspired by Daniel J. Bernstein's public domain nistp224 implementation
 * and Adam Langley's public domain 64-bit C implementation of curve25519
 */

#include <stdint.h>
#include <string.h>

typedef __uint128_t uint128_t;

namespace ecp_utils
{
    void flip_endian(uint8_t *out, const uint8_t *in, unsigned len);
}

namespace p224
{

/******************************************************************************/
/*-
 * INTERNAL REPRESENTATION OF FIELD ELEMENTS
 *
 * Field elements are represented as a_0 + 2^56*a_1 + 2^112*a_2 + 2^168*a_3
 * using 64-bit coefficients called 'limbs',
 * and sometimes (for multiplication results) as
 * b_0 + 2^56*b_1 + 2^112*b_2 + 2^168*b_3 + 2^224*b_4 + 2^280*b_5 + 2^336*b_6
 * using 128-bit coefficients called 'widelimbs'.
 * A 4-limb representation is an 'felem';
 * a 7-widelimb representation is a 'widefelem'.
 * Even within felems, bits of adjacent limbs overlap, and we don't always
 * reduce the representations: we ensure that inputs to each felem
 * multiplication satisfy a_i < 2^60, so outputs satisfy b_i < 4*2^60*2^60,
 * and fit into a 128-bit word without overflow. The coefficients are then
 * again partially reduced to obtain an felem satisfying a_i < 2^57.
 * We only reduce to the unique minimal representation at the end of the
 * computation.
 */

typedef uint64_t limb;
typedef limb felem[4];

/* Encapsulate the functionality related to the elliptic curve which is useful
 * for abstracting amongst the NIST curves
 */
class traits 
{
public:
    // Type of a field element
    typedef felem       felem_type;

    // Type of a generic scalar (little endian!)
    typedef uint8_t     scalar_type[28];

    // Type of a precomputation table for generic scalar multiplication
    typedef felem_type precomp_table[17][3];

    // Size of a scalar in bytes
    static const size_t scalar_sz = 28;

    /* Convert little endian byte array to field element
     */
    static void
    scalar_to_felem(
        felem&              x,              // (O) Field element
        scalar_type const&  scalar          // (I) Scalar (little endian)
    );

    /* Convert field element to little endian byte array
     *
     * Requires that field element is reduced
     */
    static void
    felem_to_scalar(
        scalar_type&        scalar,         // (O) Scalar (little endian)
        felem const&        x               // (I) Field element
    );

    /* Scalar multiplication with respect to the base point using precomputed table
     * 
     * Output point (X, Y, Z) is stored in x_out, y_out, z_out and are reduced
     */
    static void
    scalarmult_base_impl(
        felem&      x_out,                  // (O) X coordinate
        felem&      y_out,                  // (O) Y coordinate
        felem&      z_out,                  // (O) Z coordinate
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
        felem&              x_out,      // (O) X coordinate
        felem&              y_out,      // (O) Y coordinate
        felem&              z_out,      // (O) Z coordinate
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
        felem           x_out,  // (O) affine x coordinate
        felem           y_out,  // (O) affine y coordinate
        felem const&    x_in,   // (I) X coordinate
        felem const&    y_in,   // (I) Y coordinate
        felem const&    z_in    // (I) Z coordinate
    );

    /* Compute the table required for 'scalarmult_impl'. In this case consists of
     *
     * 0*P, 1*P, ..., 16*P
     */
    static void
    precompute_table(
        precomp_table           table,      // (O) Precompute Table
        felem const&            X,          // (I) X coordinate in Jacobian Coordinates
        felem const&            Y,          // (I) Y coordinate in Jacobian Coordinates
        felem const&            Z           // (I) Z coordinate in Jacobian Coordinates
    );

    /* return the field element 1 */
    static void
    one(felem& out);
};

// Implementation details
namespace details
{

typedef uint8_t u8;
typedef uint64_t u64;
typedef uint128_t widelimb;
typedef widelimb widefelem[7];
typedef uint8_t felem_bytearray[28];

// Precomputed table for base point scalar multiplication
typedef felem base_precompute_table[2][16][3];
extern base_precompute_table const gmul;

void felem_reduce(felem out, const widefelem in);
void felem_assign(felem out, const felem in);
void felem_zero(felem out);
void bin28_to_felem(felem out, const u8 in[28]);
void felem_to_bin28(u8 out[28], const felem in);


/*-
 * Add two elliptic curve points in jacobian coordinates:
 * (X_1, Y_1, Z_1) + (X_2, Y_2, Z_2) = (X_3, Y_3, Z_3), where
 * X_3 = (Z_1^3 * Y_2 - Z_2^3 * Y_1)^2 - (Z_1^2 * X_2 - Z_2^2 * X_1)^3 -
 * 2 * Z_2^2 * X_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^2
 * Y_3 = (Z_1^3 * Y_2 - Z_2^3 * Y_1) * (Z_2^2 * X_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^2 - X_3) -
 *        Z_2^3 * Y_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^3
 * Z_3 = (Z_1^2 * X_2 - Z_2^2 * X_1) * (Z_1 * Z_2)
 *
 * This runs faster if 'mixed' is set, which requires Z_2 = 1 or Z_2 = 0.
 */
void point_add(
    felem           x3,     // (O) X3
    felem           y3,     // (O) Y3
    felem           z3,     // (O) Z3
    const felem     x1,     // (I) X1
    const felem     y1,     // (I) Y1
    const felem     z1,     // (I) Z1
    const int       mixed,  // (I) Assume Z2=1 or Z2=0
    const felem     x2,     // (I) X2
    const felem     y2,     // (I) Y2
    const felem     z2      // (I) Z2
);

/*-
 * Double an elliptic curve point:
 * (X', Y', Z') = 2 * (X, Y, Z), where
 * X' = (3 * (X - Z^2) * (X + Z^2))^2 - 8 * X * Y^2
 * Y' = 3 * (X - Z^2) * (X + Z^2) * (4 * X * Y^2 - X') - 8 * Y^2
 * Z' = (Y + Z)^2 - Y^2 - Z^2 = 2 * Y * Z
 * Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed,
 * while x_out == y_in is not (maybe this works, but it's not tested).
 */
void
point_double(
    felem           x_out,      // (O) X'
    felem           y_out,      // (O) Y'
    felem           z_out,      // (O) Z'
    const felem     x_in,       // (I) X
    const felem     y_in,       // (I) Y
    const felem     z_in        // (I) Z
);

/******************************************************************************/
/*-
 *                              FIELD OPERATIONS
 *
 * Field operations, using the internal representation of field elements.
 * NB! These operations are specific to our point multiplication and cannot be
 * expected to be correct in general - e.g., multiplication with a large scalar
 * will cause an overflow.
 *
 */

void felem_zero(felem out);
void felem_one(felem out);
void felem_assign(felem out, const felem in);
void felem_sum(felem out, const felem in);
void felem_neg(felem out, const felem in);

/* Subtract field elements: out -= in */
/* Assumes in[i] < 2^57 */
void felem_diff(felem out, const felem in);

/* Subtract in unreduced 128-bit mode: out -= in */
/* Assumes in[i] < 2^119 */
void widefelem_diff(widefelem out, const widefelem in);

/* Subtract in mixed mode: out128 -= in64 */
/* in[i] < 2^63 */
void felem_diff_128_64(widefelem out, const felem in);

/*
 * Multiply a field element by a scalar: out = out * scalar The scalars we
 * actually use are small, so results fit without overflow
 */
void felem_scalar(felem out, const limb scalar);

/*
 * Multiply an unreduced field element by a scalar: out = out * scalar The
 * scalars we actually use are small, so results fit without overflow
 */
void widefelem_scalar(widefelem out, const widelimb scalar);

/* Square a field element: out = in^2 */
void felem_square(widefelem out, const felem in);

/* Multiply two field elements: out = in1 * in2 */
void felem_mul(widefelem out, const felem in1, const felem in2);

/*-
 * Reduce seven 128-bit coefficients to four 64-bit coefficients.
 * Requires in[i] < 2^126,
 * ensures out[0] < 2^56, out[1] < 2^56, out[2] < 2^56, out[3] <= 2^56 + 2^16 */
void felem_reduce(felem out, const widefelem in);

/*
 * Reduce to unique minimal representation. Requires 0 <= in < 2*p (always
 * call felem_reduce first)
 */
void felem_contract(felem out, const felem in);

/*
 * Zero-check: returns 1 if input is 0, and 0 otherwise. We know that field
 * elements are reduced to in < 2^225, so we only need to check three cases:
 * 0, 2^224 - 2^96 + 1, and 2^225 - 2^97 + 2
 */
limb felem_is_zero(const felem in);

/* Invert a field element */
/* Computation chain copied from djb's code */
void felem_inv(felem out, const felem in);

/*
 * Copy in constant time: if icopy == 1, copy in to out, if icopy == 0, copy
 * out to itself.
 */
void copy_conditional(felem out, const felem in, limb icopy);


/*
 * select_point selects the |idx|th point from a precomputation table and
 * copies it to out.
 * The pre_comp array argument should be size of |size| argument
 */
void select_point(const u64 idx, unsigned int size,
                         const felem pre_comp[][3], felem out[3]);

/* get_bit returns the |i|th bit in |in| */
char get_bit(const felem_bytearray in, unsigned i);

} // namespace details

} // namespace p224


namespace ecp_utils
{
   /*
    * This function looks at 5+1 scalar bits (5 current, 1 adjacent less
    * significant bit), and recodes them into a signed digit for use in fast point
    * multiplication: the use of signed rather than unsigned digits means that
    * fewer points need to be precomputed, given that point inversion is easy
    * (a precomputed point dP makes -dP available as well).
    *
    * BACKGROUND:
    *
    * Signed digits for multiplication were introduced by Booth ("A signed binary
    * multiplication technique", Quart. Journ. Mech. and Applied Math., vol. IV,
    * pt. 2 (1951), pp. 236-240), in that case for multiplication of integers.
    * Booth's original encoding did not generally improve the density of nonzero
    * digits over the binary representation, and was merely meant to simplify the
    * handling of signed factors given in two's complement; but it has since been
    * shown to be the basis of various signed-digit representations that do have
    * further advantages, including the wNAF, using the following general approach:
    *
    * (1) Given a binary representation
    *
    *       b_k  ...  b_2  b_1  b_0,
    *
    *     of a nonnegative integer (b_k in {0, 1}), rewrite it in digits 0, 1, -1
    *     by using bit-wise subtraction as follows:
    *
    *        b_k b_(k-1)  ...  b_2  b_1  b_0
    *      -     b_k      ...  b_3  b_2  b_1  b_0
    *       -------------------------------------
    *        s_k b_(k-1)  ...  s_3  s_2  s_1  s_0
    *
    *     A left-shift followed by subtraction of the original value yields a new
    *     representation of the same value, using signed bits s_i = b_(i+1) - b_i.
    *     This representation from Booth's paper has since appeared in the
    *     literature under a variety of different names including "reversed binary
    *     form", "alternating greedy expansion", "mutual opposite form", and
    *     "sign-alternating {+-1}-representation".
    *
    *     An interesting property is that among the nonzero bits, values 1 and -1
    *     strictly alternate.
    *
    * (2) Various window schemes can be applied to the Booth representation of
    *     integers: for example, right-to-left sliding windows yield the wNAF
    *     (a signed-digit encoding independently discovered by various researchers
    *     in the 1990s), and left-to-right sliding windows yield a left-to-right
    *     equivalent of the wNAF (independently discovered by various researchers
    *     around 2004).
    *
    * To prevent leaking information through side channels in point multiplication,
    * we need to recode the given integer into a regular pattern: sliding windows
    * as in wNAFs won't do, we need their fixed-window equivalent -- which is a few
    * decades older: we'll be using the so-called "modified Booth encoding" due to
    * MacSorley ("High-speed arithmetic in binary computers", Proc. IRE, vol. 49
    * (1961), pp. 67-91), in a radix-2^5 setting.  That is, we always combine five
    * signed bits into a signed digit:
    *
    *       s_(4j + 4) s_(4j + 3) s_(4j + 2) s_(4j + 1) s_(4j)
    *
    * The sign-alternating property implies that the resulting digit values are
    * integers from -16 to 16.
    *
    * Of course, we don't actually need to compute the signed digits s_i as an
    * intermediate step (that's just a nice way to see how this scheme relates
    * to the wNAF): a direct computation obtains the recoded digit from the
    * six bits b_(4j + 4) ... b_(4j - 1).
    *
    * This function takes those five bits as an integer (0 .. 63), writing the
    * recoded digit to *sign (0 for positive, 1 for negative) and *digit (absolute
    * value, in the range 0 .. 8).  Note that this integer essentially provides the
    * input bits "shifted to the left" by one position: for example, the input to
    * compute the least significant recoded digit, given that there's no bit b_-1,
    * has to be b_4 b_3 b_2 b_1 b_0 0.
    *
    */
    void ec_GFp_nistp_recode_scalar_bits(unsigned char *sign, unsigned char *digit, unsigned char in);
}

