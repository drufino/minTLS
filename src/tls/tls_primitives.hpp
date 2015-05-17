/* Low-level cryptographic primitives used by TLS
 * 
 * Primary reference
 *   [1] http://tools.ietf.org/html/rfc5246
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_primitives_hpp
#define tf_tls_primitives_hpp
#include <tls/tls_ciphersuites.hpp>

namespace asn1
{
    class AlgorithmIdentifier;
}

class BigInt;

// Calculate data for ServerFinished and ClientFinished messages
void
calculate_finished_data(
    std::vector<uint8_t>&           verify_data,// (O) Verify Data
    std::vector<uint8_t> const&     master_secret, // (I) Master Secret
    std::vector<uint8_t> const&     data,       // (I) Total handshake data
    CipherSuite                     cipher,     // (I) Cipher
    const char *                    label       // (I) Label
);

// Implement the PRF for TLS1.2. RFC-5246 Section 5
void
TLSPRF(
    std::vector<uint8_t>&           prf_output,     // (O) PRF Output
    PRFMode                         prf_mode,       // (I) PRF mode (i.e. hash variant used for HMAC)
    size_t const                    sz,             // (I) Number of bytes needed
    std::vector<uint8_t> const&     secret,         // (I) Secret
    char const *                    label,          // (I) Label (null-terminated string)
    std::vector<uint8_t> const&     seed            // (I) Seed
);

// Verify a signature, making sure that the TLS algorithm matches the x509 algorithm
// Currently only RSA (PKCS v1.5) signatures sure supported.
//
// Returns mintls_success on success
//         mintls_err_*   otherwise
mintls_error
tls_verify(
    std::vector<uint8_t> const&     tls_signature,      // (I) TLS Signature
    std::vector<uint8_t> const&     data,               // (I) Data
    MinTLS_Hash                     hash_algo,          // (I) Hash Algorithm
    TLSSignatureAlgorithm           tls_sig_algo,       // (I) Signature Algorithm from TLS
    asn1::AlgorithmIdentifier const&crt_sig_algo,       // (I) Signature Algorithm from the certificate
    std::vector<uint8_t> const&     crt_sig_key         // (I) Signature Public Key from the certificate
);

// Forward declaration
namespace asn1
{
    class AlgorithmIdentifier;
}

// Signature verification
//
// Return mintls_success            on success
//        mintls_err_decode_error   in case the public key is malformed or sig_len isnt equal to modulus size
mintls_error
pubkey_verify(
    std::vector<uint8_t> const&     signature,          // (I) TLS Signature
    std::vector<uint8_t> const&     data,               // (I) Data to be signed
    asn1::AlgorithmIdentifier const&sig_algo,           // (I) Signature Algorithm
    asn1::AlgorithmIdentifier const&pk_algo,            // (I) Public Key Algorithm
    std::vector<uint8_t> const&     key                 // (I) Public Key
);

// Perform diffie-hellman key agreement. This consists of
//
// 1) Deserialize the server's public key and signature
// 2) Verify the authenticity of the key using the signature and supplied certificate
// 3) Generate a random client private key and public key
// 4) Generate the shared secret
//
// NB the client private key is discarded once the operation is completed.
//
// RFC-5246 8.1.2
mintls_error
dh_key_agreement(
    std::vector<uint8_t> const&     server_kex_msg,     // (I) ServerKexMessage
    KexMethod const                 kex_method,         // (I) Key Exchange Method
    std::vector<uint8_t> const&     client_random,      // (I) Client Random
    std::vector<uint8_t> const&     server_random,      // (I) Server Random
    asn1::AlgorithmIdentifier       crt_sig_algo,       // (I) Signature Algorithm
    std::vector<uint8_t> const&     crt_sig_key,        // (I) Signature Public Key
    std::vector<uint8_t> &          public_key,         // (O) Public Key
    std::vector<uint8_t> &          premaster_secret    // (O) Shared secret
);


// TLS1.2 Expand pre-master secret RFC-5246 8.1
void
expand_premaster_secret(
    std::vector<uint8_t> const&     premaster_secret,   // (I) Premaster secret
    PRFMode                         prf_mode,           // (I) PRF Mode
    std::vector<uint8_t> const&     client_random,      // (I) Client Random
    std::vector<uint8_t> const&     server_random,      // (I) Server Random
    std::vector<uint8_t>&           master_secret       // (O) Master secret
);

// TLS1.2 Expand master secret into MAC keys and encryption keys RFC-5246 6.3 
void
expand_master_secret(
    std::vector<uint8_t> const&     master_secret,      // (I) Master secret
    std::vector<uint8_t> const&     client_random,      // (I) Client Random
    std::vector<uint8_t> const&     server_random,      // (I) Server Random
    CipherSuite                     cipher_suite,       // (I) Cipher Suite
    std::vector<uint8_t>&           client_mac_key,     // (O) Client MAC key
    std::vector<uint8_t>&           server_mac_key,     // (O) Server MAC key
    std::vector<uint8_t>&           client_key,         // (O) Client key
    std::vector<uint8_t>&           server_key          // (O) Server key
);





template<typename T>
std::vector<T> operator+(std::vector<T> const& lhs, std::vector<T> const& rhs)
{
    std::vector<T> ret = lhs;
    ret.reserve(ret.size() + rhs.size());
    std::copy(rhs.begin(),rhs.end(),std::back_inserter(ret));
    return ret;
}

#endif
