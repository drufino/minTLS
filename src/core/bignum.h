/*
 *  Multi-precision integer library
 *
 *  Copyright (C) 2006-2007  Christophe Devine
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of XySSL nor the names of its contributors may be
 *      used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \file bignum.h
 */
#ifndef XYSSL_BIGNUM_H
#define XYSSL_BIGNUM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define XYSSL_ERR_MPI_FILE_IO_ERROR                     -0x0002
#define XYSSL_ERR_MPI_BAD_INPUT_DATA                    -0x0004
#define XYSSL_ERR_MPI_INVALID_CHARACTER                 -0x0006
#define XYSSL_ERR_MPI_BUFFER_TOO_SMALL                  -0x0008
#define XYSSL_ERR_MPI_NEGATIVE_VALUE                    -0x000A
#define XYSSL_ERR_MPI_DIVISION_BY_ZERO                  -0x000C
#define XYSSL_ERR_MPI_NOT_ACCEPTABLE                    -0x000E

/*
 * Define the base integer type, architecture-wise
 */
typedef uint32_t t_int;
typedef uint64_t t_dbl; 

/**
 * \brief          MPI structure
 */
typedef struct
{
    int s;              /*!<  integer sign      */
    int n;              /*!<  total # of limbs  */
    t_int *p;           /*!<  pointer to limbs  */
}
mpi;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize one or more mpi
 */
void mpi_init( mpi *X, ... );

/**
 * \brief          Unallocate one or more mpi
 */
void mpi_free( mpi *X, ... );

/**
 * \brief          Enlarge to the specified number of limbs
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_grow( mpi *X, int nblimbs );

/**
 * \brief          Copy the contents of Y into X
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_copy( mpi *X, mpi const *Y );

/**
 * \brief          Swap the contents of X and Y
 */
void mpi_swap( mpi *X, mpi *Y );

/**
 * \brief          Set value from integer
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_lset( mpi *X, int z );

/**
 * \brief          Return the number of least significant bits
 */
int mpi_lsb( mpi const *X );

/**
 * \brief          Return the number of most significant bits
 */
int mpi_msb( mpi const *X );

/**
 * \brief          Return the total size in bytes
 */
int mpi_size( mpi const *X );

/**
 * \brief          Import from an ASCII string
 *
 * \param X        destination mpi
 * \param radix    input numeric base
 * \param s        null-terminated string buffer
 *
 * \return         0 if successful, or an XYSSL_ERR_MPI_XXX error code
 */
int mpi_read_string( mpi *X, int radix, char *s );

/**
 * \brief          Export into an ASCII string
 *
 * \param X        source mpi
 * \param radix    output numeric base
 * \param s        string buffer
 * \param slen     string buffer size
 *
 * \return         0 if successful, or an XYSSL_ERR_MPI_XXX error code
 *
 * \note           Call this function with *slen = 0 to obtain the
 *                 minimum required buffer size in *slen.
 */
int mpi_write_string( mpi const *X, int radix, char *s, int *slen );

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        destination mpi
 * \param buf      input buffer
 * \param buflen   input buffer size
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_read_binary( mpi *X, unsigned char *buf, int buflen );

/**
 * \brief          Export X into unsigned binary data, big endian
 *
 * \param X        source mpi
 * \param buf      output buffer
 * \param buflen   output buffer size
 *
 * \return         0 if successful,
 *                 XYSSL_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
 *
 * \note           Call this function with *buflen = 0 to obtain the
 *                 minimum required buffer size in *buflen.
 */
int mpi_write_binary( mpi const *X, unsigned char *buf, int buflen );

/**
 * \brief          Left-shift: X <<= count
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_shift_l( mpi *X, int count );

/**
 * \brief          Right-shift: X >>= count
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_shift_r( mpi *X, int count );

/**
 * \brief          Compare unsigned values
 *
 * \return         1 if |X| is greater than |Y|,
 *                -1 if |X| is lesser  than |Y| or
 *                 0 if |X| is equal to |Y|
 */
int mpi_cmp_abs( mpi const *X, mpi const *Y );

/**
 * \brief          Compare signed values
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser  than Y or
 *                 0 if X is equal to Y
 */
int mpi_cmp_mpi( mpi const *X, mpi const *Y );

/**
 * \brief          Compare signed values
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser  than z or
 *                 0 if X is equal to z
 */
int mpi_cmp_int( mpi const *X, int z );

/**
 * \brief          Unsigned addition: X = |A| + |B|
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_add_abs( mpi *X, mpi const *A, mpi const *B );

/**
 * \brief          Unsigned substraction: X = |A| - |B|
 *
 * \return         0 if successful,
 *                 XYSSL_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
int mpi_sub_abs( mpi *X, mpi const *A, mpi const *B );

/**
 * \brief          Signed addition: X = A + B
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_add_mpi( mpi *X, mpi const *A, mpi const *B );

/**
 * \brief          Signed substraction: X = A - B
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_sub_mpi( mpi *X, mpi const *A, mpi const *B );

/**
 * \brief          Signed addition: X = A + b
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_add_int( mpi *X, mpi const *A, int b );

/**
 * \brief          Signed substraction: X = A - b
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_sub_int( mpi *X, mpi const *A, int b );

/**
 * \brief          Baseline multiplication: X = A * B
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_mul_mpi( mpi *X, mpi const *A, mpi const *B );

/**
 * \brief          Baseline multiplication: X = A * b
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_mul_int( mpi *X, mpi const *A, t_int b );

/**
 * \brief          Division by mpi: A = Q * B + R
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note           Either Q or R can be NULL.
 */
int mpi_div_mpi( mpi *Q, mpi *R, mpi const* A, mpi const *B );

/**
 * \brief          Division by int: A = Q * b + R
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note           Either Q or R can be NULL.
 */
int mpi_div_int( mpi *Q, mpi *R, mpi *A, int b );

/**
 * \brief          Modulo: R = A mod B
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0
 */
int mpi_mod_mpi( mpi *R, mpi const *A, mpi const *B );

/**
 * \brief          Modulo: r = A mod b
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0
 */
int mpi_mod_int( t_int *r, mpi const *A, int b );

/**
 * \brief          Sliding-window exponentiation: X = A^E mod N
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or even
 *
 * \note           _RR is used to avoid re-computing R*R mod N across
 *                 multiple calls, which speeds up things a bit. It can
 *                 be set to NULL if the extra performance is unneeded.
 */
int mpi_exp_mod( mpi *X, mpi const *A, mpi const *E, mpi const *N, mpi *_RR );

/**
 * \brief          Greatest common divisor: G = gcd(A, B)
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_gcd( mpi *G, mpi const *A, mpi const *B );

/**
 * \brief          Modular inverse: X = A^-1 mod N
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or nil
 *                 XYSSL_ERR_MPI_NOT_ACCEPTABLE if A has no inverse mod N
 */
int mpi_inv_mod( mpi *X, mpi const *A, mpi const *N );

/**
 * \brief          Miller-Rabin primality test
 *
 * \return         0 if successful (probably prime),
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_NOT_ACCEPTABLE if X is not prime
 */
int mpi_is_prime( mpi *X, int (*f_rng)(void *), void *p_rng );

/**
 * \brief          Prime number generation
 *
 * \param X        destination mpi
 * \param nbits    required size of X in bits
 * \param dh_flag  if 1, then (X-1)/2 will be prime too
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 1 if memory allocation failed,
 *                 XYSSL_ERR_MPI_BAD_INPUT_DATA if nbits is < 3
 */
int mpi_gen_prime( mpi *X, int nbits, int dh_flag,
                   int (*f_rng)(void *), void *p_rng );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mpi_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* bignum.h */
