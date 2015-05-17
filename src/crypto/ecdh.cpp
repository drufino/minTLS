#include "ecdh.h"
#include "ecp_p224.h"
#include "ecp_p256.h"
/*
 * We implement a genericized version of the elliptic curve operations so that it is
 * straight-forward to add new implementations
 */

/* Encode into uncompressed format using [3] 4.3.6
 */
template<typename traits>
void
encode_point(
    uint8_t *                           point,          // (O) Encoded Point (57 bytes)
    typename traits::felem_type const&  x,              // (I) Affine X coordinate
    typename traits::felem_type const&  y               // (I) Affine Y coordinate
)
{
    // Convert from sparse limbs to little endian
    uint8_t x_bin[traits::scalar_sz], y_bin[traits::scalar_sz];
    traits::felem_to_scalar(x_bin, x);
    traits::felem_to_scalar(y_bin, y);

    // Convert from little endian to big endian as required by the encoding
    point[0] = 0x04;
    ecp_utils::flip_endian(point+1,                       x_bin,  traits::scalar_sz);
    ecp_utils::flip_endian(point+1+traits::scalar_sz,     y_bin,  traits::scalar_sz);
}

// Decode affine point using uncompressed point format [3] 4.3.6
template<typename traits>
int
decode_point(
    typename traits::felem_type &   x,      // (I) Affine X coordinate
    typename traits::felem_type &   y,      // (I) Affine Y coordinate
    uint8_t const *                 point   // (O) Encoded Point (57 bytes)
)
{
    if (point[0] != 0x04)
    {
        return -1;
    }

    // Decode point and convert to little endian
    uint8_t x_bin[traits::scalar_sz], y_bin[traits::scalar_sz];
    ecp_utils::flip_endian(x_bin,point+1,                   traits::scalar_sz);
    ecp_utils::flip_endian(y_bin,point+1+traits::scalar_sz, traits::scalar_sz);

    // Convert into field elements
    traits::scalar_to_felem(x,x_bin);
    traits::scalar_to_felem(y,y_bin);

    return 0;
}

template<typename traits>
int
ecdh_base_scalar_mult(
    uint8_t const *     scalar_be,      // (I) Scalar
    size_t const        scalar_sz,      // (I) Scalar size
    uint8_t *           point           // (O) Point (uncompressed using [5] 4.3.6)
)
{
    // Check the input size is correct
    if (scalar_sz != traits::scalar_sz)
    {
        return -1;
    }

    // Field element type
    typedef typename traits::felem_type felem;

    uint8_t scalar_le[traits::scalar_sz];
    ecp_utils::flip_endian(scalar_le, scalar_be, traits::scalar_sz);

    // Calculate scalar multiple in Jacobian coordinates
    felem X,Y,Z;
    traits::scalarmult_base_impl(
        X,          // (O) X-coordinate
        Y,          // (O) Y-coordinate
        Z,          // (O) Z-coordinate
        scalar_le  // (I) Base point scalar
    );

    // Convert to affine coordinates
    felem x,y;
    if (traits::jacobian_to_affine(
            x,          // (O) x coordinate
            y,          // (O) y coordinate
            X,          // (I) X coordinate
            Y,          // (I) Y coordinate
            Z           // (I) Z coordinate
        ))
    {
        return -1;
    }

    // Use X6.92 encoding, uncompressed
    encode_point<traits>(
        point,          // (O) Point
        x,              // (I) Affine X coordinate
        y               // (I) Affine Y coordinate
    );

    return 0;
}

template<typename traits>
int
ecdh_scalar_mult(
    uint8_t const *     scalar_be,      // (I) Scalar (big endian using [5] 4.3.3)
    size_t const        scalar_sz,      // (I) Scalar size
    uint8_t const *     base_point,     // (I) Base point (uncompressed using [5] 4.3.6)
    size_t const        base_point_sz,  // (I) Base point size
    uint8_t *           point           // (O) Point (uncompressed using [5] 4.3.6)
)
{
    if (scalar_sz != traits::scalar_sz || base_point_sz != (traits::scalar_sz*2+1))
    {
        return -1;
    }
    // Field element type
    typedef typename traits::felem_type felem;

    uint8_t scalar_le[traits::scalar_sz];
    ecp_utils::flip_endian(scalar_le, scalar_be, traits::scalar_sz);

    // Extract out base point
    felem X_base, Y_base, Z_base;
    traits::one(Z_base);

    if (decode_point<traits>(
            X_base,     // (O) X coordinate
            Y_base,     // (O) Y coordinate
            base_point  // (I) Base point
        ))
    {
        return -1;
    }

    // Compute table of small multiples
    typename traits::precomp_table mul;
    traits::precompute_table(
        mul,    // (O) Precompute Table
        X_base, // (I) X coordinate in Jacobian Coordinates
        Y_base, // (I) Y coordinate in Jacobian Coordinates
        Z_base  // (I) Z coordinate in Jacobian Coordinates
    );

    // Calculate scalar multiple in Jacobian coordinates
    felem X,Y,Z;
    traits::scalarmult_impl(
        X,          // (O) X-coordinate
        Y,          // (O) Y-coordinate
        Z,          // (O) Z-coordinate
        scalar_le,  // (I) Base point scalar
        mul         // (I) Pre computation table for base point 
    );

    // Convert to affine coordinates
    felem x,y;
    if (traits::jacobian_to_affine(
            x,          // (O) affine x coordinate
            y,          // (O) affine y coordinate
            X,          // (I) X coordinate
            Y,          // (I) Y coordinate
            Z           // (I) Z coordinate
        ))
    {
        return -1;
    }

    // Use X6.92 encoding, uncompressed
    encode_point<traits>(
        point,          // (O) Point
        x,              // (I) Affine X coordinate
        y               // (I) Affine Y coordinate
    );

    return 0;
}

extern "C"
{

/* Return size of scalar/private key
 */
size_t mintls_ecdh_scalar_size(MinTLS_NamedCurve curve)
{
    switch (curve)
    {
    case mintls_secp224r1:
        return p224::traits::scalar_sz;
    case mintls_secp256r1:
        return p256::traits::scalar_sz;
    default:
        return -1;
    }
}

/* Return size of point/public key
 *
 * Encoding is in uncompressed form [5] Section 4.3.6
 */
size_t mintls_ecdh_point_size(MinTLS_NamedCurve curve)
{
    return 2*mintls_ecdh_scalar_size(curve)+1;
}


int
mintls_ecdh_base_scalar_mult(
    MinTLS_NamedCurve   curve,          // (I) Curve
    uint8_t const *     scalar_be,      // (I) Scalar
    size_t const        scalar_sz,      // (I) Scalar size
    uint8_t *           point           // (O) Point (uncompressed using [5] 4.3.6)
)
{
    switch (curve)
    {
    case mintls_secp224r1:
        return ecdh_base_scalar_mult<p224::traits>(scalar_be, scalar_sz, point);
    case mintls_secp256r1:
        return ecdh_base_scalar_mult<p256::traits>(scalar_be, scalar_sz, point);
    default:
        return -1;
    }
}

int
mintls_ecdh_scalar_mult(
    MinTLS_NamedCurve   curve,          // (I) Curve
    uint8_t const *     scalar_be,      // (I) Scalar (big endian using [5] 4.3.3)
    size_t const        scalar_sz,      // (I) Scalar size
    uint8_t const *     base_point,     // (I) Base point (uncompressed using [5] 4.3.6)
    size_t const        base_point_sz,  // (I) Base point size
    uint8_t *           point           // (O) Point (uncompressed using [5] 4.3.6)
)
{
    switch (curve)
    {
    case mintls_secp224r1:
        return ecdh_scalar_mult<p224::traits>(scalar_be, scalar_sz, base_point, base_point_sz, point);
    case mintls_secp256r1:
        return ecdh_scalar_mult<p256::traits>(scalar_be, scalar_sz, base_point, base_point_sz, point);
    default:
        return -1;
    }
}

} // extern "C"
