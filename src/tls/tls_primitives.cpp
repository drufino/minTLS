/*
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "tls_primitives.hpp"
#include <tls/tls_ecc.hpp>
#include <tls/tls_protocol.hpp>
#include <asn1/asn1_objects.hpp>
#include <core/tf_debug.hpp>
#include <hmac.h>
#include <random.h>
#include <core/portability.h>

void
calculate_finished_data(
    std::vector<uint8_t>&           verify_data,// (O) Verify Data
    std::vector<uint8_t> const&     master_secret, // (I) Master Secret
    std::vector<uint8_t> const&     data,       // (I) Total handshake data
    CipherSuite                     cipher,     // (I) Cipher
    const char *                    label       // (I) Label
)
{
    MinTLS_Hash  hash_version = CipherSuites::hash_algorithm(cipher);

    tf_debug("[*] Calculating Finished verify_data [%d]", data.size());
    // First hash the handshake messages
    std::vector<uint8_t> hash(mintls_hash_tag_length(hash_version));
    mintls_hash(hash_version,&data[0],data.size(),&hash[0]);

    // Now apply the PRF
    PRFMode prf_mode = CipherSuites::prf_mode(cipher);

    verify_data.clear();
    TLSPRF(
        verify_data,        // (O) PRF Output
        prf_mode,           // (I) PRF mode (i.e. hash variant used for HMAC)
        12,                 // (I) Number of bytes needed
        master_secret,      // (I) Secret
        label,              // (I) Label (null-terminated string)
        hash                // (I) Seed
    );
}

void
TLSPRF(
    std::vector<uint8_t>&           prf_output,     // (O) PRF Output
    PRFMode                         prf_mode,       // (I) PRF mode (i.e. hash variant used for HMAC)
    size_t const                    sz,             // (I) Number of bytes needed
    std::vector<uint8_t> const&     secret,         // (I) Secret
    char const *                    label,          // (I) Label (null-terminated string)
    std::vector<uint8_t> const&     seed            // (I) Seed
)
{
    MinTLS_Hash  hash_mode;

    switch (prf_mode.underlying())
    {
    case PRFModes::PRF_SHA224:
        hash_mode = MinTLS_SHA_224;
        break;
    case PRFModes::PRF_SHA256:
        hash_mode = MinTLS_SHA_256;
        break;
    case PRFModes::PRF_SHA384:
        hash_mode = MinTLS_SHA_384;
        break;
    case PRFModes::PRF_SHA512:
        hash_mode = MinTLS_SHA_512;
        break;
    default:
        throw std::runtime_error("Unsupported PRFMode");
    }

    // Figure out the tag length
    size_t const tag_length = mintls_hash_tag_length(hash_mode);

    // Figure out the number of interations needed
    size_t nBlocks(0); size_t nBytes(0);
    while (nBytes < sz)
    {
        nBlocks++;
        nBytes += tag_length;
    }

    // Length of the label
    size_t const label_sz = strlen(label);

    // Allocate enough space
    prf_output.assign(nBytes,0);

    // Initialize A(1)
	VLA(uint8_t, A, tag_length);
    memset(A,0, tag_length);

    mintls_hmac_context ctx;
    mintls_hmac_init(&ctx, hash_mode, tag_length, &secret[0], secret.size());
    mintls_hmac_update(&ctx, (uint8_t const *)label, label_sz);
    mintls_hmac_update(&ctx, &seed[0], seed.size());
    mintls_hmac_finish(&ctx, A);

    for (size_t iBlock = 0; iBlock < nBlocks; ++iBlock)
    {
        // Calculate P_hash
        mintls_hmac_init(&ctx, hash_mode, tag_length, &secret[0], secret.size());
        mintls_hmac_update(&ctx, A, tag_length);
        mintls_hmac_update(&ctx, (uint8_t const *)label, label_sz);
        mintls_hmac_update(&ctx, &seed[0], seed.size());
        mintls_hmac_finish(&ctx, &prf_output[tag_length*iBlock]);

        // Calculate A(i+1)
        if (iBlock != nBlocks - 1)
        {
            mintls_hmac_do(
                hash_mode,          // (I) Underlying hash
                &secret[0],         // (I) Key
                secret.size(),      // (I) Key length
                A,                  // (I) Input data
                tag_length,         // (I) Input length
                A,                  // (O) Output
                tag_length          // (I) Required tag size (must be <= underlying hash tag length. Set to 0 to default to mac length)
            );
        }
    }

    // Erase sensitive data
	memset(A, 0, tag_length);

    // Reduce size to that requested
    prf_output.resize(sz);
}

mintls_error
tls_verify(
    std::vector<uint8_t> const&     tls_signature,      // (I) TLS Signature
    std::vector<uint8_t> const&     data,               // (I) Data
    MinTLS_Hash                     hash_algo,          // (I) Hash Algorithm
    TLSSignatureAlgorithm           tls_sig_algo,       // (I) Signature Algorithm from TLS
    asn1::AlgorithmIdentifier const&crt_sig_algo,       // (I) Signature Algorithm from the certificate
    std::vector<uint8_t> const&     crt_sig_key         // (I) Signature Public Key from the certificate
)
{
    // Make sure certificate algorithm matches tls algorithm
    std::string s_crt_sig_algo = crt_sig_algo.oid.to_string();
    MinTLS_SignatureAlgorithm sig_algo = CipherSuites::sig_algo(tls_sig_algo);

    if (mintls_pubkey_algo(s_crt_sig_algo.c_str()) != sig_algo)
    {
        tf_debug("[E] Mismatch between Certificate Signature Algorithm (%s) and TLS Signature Algorithm (%d)",
            s_crt_sig_algo.c_str(),
            sig_algo
        );
        return mintls_err_illegal_parameter;
    }

    MinTLS_Hash  crt_sig_algo_hash = mintls_pubkey_algo_hash(s_crt_sig_algo.c_str());
    if (crt_sig_algo_hash != (MinTLS_Hash )0 && crt_sig_algo_hash != hash_algo)
    {
        tf_debug("[E] Mismatch between Certificate Signature Hash (%d) and TLS Signature Hash (%d)",
            crt_sig_algo_hash,
            hash_algo
        );
        return mintls_err_illegal_parameter;
    }

    return
    mintls_pubkey_verify(
        &tls_signature[0],        // (I) Signature
        tls_signature.size(),     // (I) Signature length
        sig_algo,                 // (I) Signature Algorithm
        hash_algo,                // (I) Hash Algorithm
        &data[0],                 // (I) Message
        data.size(),              // (I) Message length (bytes)
        &crt_sig_key[0],          // (I) Public Key (Usually ASN.1 Encoded)
        crt_sig_key.size()        // (I) Public Key Length
    );
}

mintls_error
dh_verify(
    std::vector<uint8_t> const&     dh_params,          // (I) DH Params
    std::vector<uint8_t> const&     dh_sig,             // (I) Signature Block
    KexMethod const&                kex_method,         // (I) Key Exchange Method
    std::vector<uint8_t> const&     client_random,      // (I) Client Random
    std::vector<uint8_t> const&     server_random,      // (I) Server Random
    asn1::AlgorithmIdentifier const&crt_sig_algo,       // (I) Signature Algorithm
    std::vector<uint8_t> const&     crt_sig_key         // (I) Signature Public Key
)
{
    switch (kex_method.underlying())
    {
    case KexMethods::DH_anon:
    case KexMethods::ECDH_anon:
        if (dh_sig.size() != 0)
        {
            return mintls_err_decode_error;
        }
        else
        {
            return mintls_success;
        }
        break;
    case KexMethods::DHE_RSA:
    case KexMethods::ECDHE_RSA:
        {
            iarchive ar(&dh_sig[0], dh_sig.size());

            // Extract signature
            MinTLS_Hash               hash_algo;
            TLSSignatureAlgorithm   sig_algo;
            std::vector<uint8_t>    signature;
            ar & hash_algo & sig_algo & signature;

            if (kex_method == KexMethods::DHE_RSA && sig_algo != TLSSignatureAlgorithms::RSA)
            {
                return mintls_err_illegal_parameter;
            }
            else if (kex_method == KexMethods::DHE_DSS && sig_algo != TLSSignatureAlgorithms::DSA)
            {
                return mintls_err_illegal_parameter;
            }

            // Shouldn't have any data left
            if (ar.left() > 0)
            {
                return mintls_err_decode_error;
            }

            // Perform the verification
            std::vector<uint8_t> sig_data = client_random + server_random + dh_params;

            mintls_error verify_res =
            tls_verify(
                signature,      // (I) TLS Signature
                sig_data,       // (I) Data
                hash_algo,      // (I) Hash Algorithm
                sig_algo,       // (I) Signature Algorithm from TLS
                crt_sig_algo,   // (I) Signature Algorithm from the certificate
                crt_sig_key     // (I) Signature Public Key from the certificate
            );
            return verify_res;
        }
        break;
    default:
        return mintls_err_decode_error;
    }
}

struct ServerDHParams
{
public:
    void serialize(archive& ar)
    {
        ar & p & g & g_a;
    }

    BigInt      p;      // Prime modulus
    BigInt      g;      // Generator
    BigInt      g_a;    // Other party's public key
};


// RFC-4492 Section 5.4
struct ServerECDHParams
{
public:
    void serialize(archive& ar)
    {
        ar & curve_params & ec_point;
    }

    ECParameters    curve_params;
    ECPoint         ec_point;
};

std::vector<uint8_t>
ecdh_base_scalar_mult(
    MinTLS_NamedCurve const     curve,          // (I) Curve
    std::vector<uint8_t> const& scalar          // (I) Scalar (big endian using [5] 4.3.3)
)
{
    std::vector<uint8_t> res(mintls_ecdh_point_size(curve));

    if (0 != 
        mintls_ecdh_base_scalar_mult(
            curve,              // (I) Curve
            &scalar[0],         // (I) Scalar (big endian using [5] 4.3.3)
            scalar.size(),      // (I) Size of the scalar
            &res[0]             // (O) Point (uncompressed using [5] 4.3.6)
        ))
    {
        throw TLSException("Error performing ECC DH", mintls_err_decode_error);
    }

    return res;
}

std::vector<uint8_t>
ecdh_scalar_mult(
    MinTLS_NamedCurve const     curve,          // (I) Curve
    std::vector<uint8_t> const& scalar,         // (I) Scalar (big endian using [5] 4.3.3)
    std::vector<uint8_t> const& point           // (I) Base Point (uncompressed using [5] 4.3.6)
)
{
    std::vector<uint8_t> res(mintls_ecdh_point_size(curve));

    if (0 != 
        mintls_ecdh_scalar_mult(
            curve,              // (I) Curve
            &scalar[0],         // (I) Scalar (big endian using [5] 4.3.3)
            scalar.size(),      // (I) Size of the scalar
            &point[0],          // (I) Base point (uncompressed using [5] 4.3.6)
            point.size(),       // (I) Base point size
            &res[0]             // (O) Point (uncompressed using [5] 4.3.6)
        ))
    {
        throw TLSException("Error performing ECC DH", mintls_err_decode_error);
    }

    return res;
}

// RFC-5246 Section 7.4.3
// RFC-4492 Section 5.4
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
)
{
    enum KexType
    {
        ff_dhe=0,   // Finite Field Diffie Hellman
        ecdhe =1    // Elliptic Curve Diffie Hellman
    };

    KexType kex_type;

    switch (kex_method.underlying())
    {
    case KexMethods::DH_anon:
    case KexMethods::DHE_RSA:
        kex_type = ff_dhe;
        break;
    case KexMethods::ECDH_anon:
    case KexMethods::ECDHE_RSA:
        kex_type = ecdhe;
        break;
    default:
        tf_debug("[E] Unrecognised kex_method %d", kex_method.underlying());
        return mintls_err_illegal_parameter;
    }

    // Deserialize the diffie hellman parmeters
    iarchive ar(&server_kex_msg[0], server_kex_msg.size());
    ServerDHParams      dh_params;
    ServerECDHParams    ecdh_params;
    if (kex_type == ff_dhe)
    {
        ar & dh_params;
    }
    else if (kex_type == ecdhe)
    {
        ar & ecdh_params;
    }
    else
    {
        return mintls_err_illegal_parameter;
    }

    // Verify the diffie-hellman parameters 
    std::vector<uint8_t> raw_dh_params(server_kex_msg.begin(), server_kex_msg.begin() + ar.size());
    std::vector<uint8_t> dh_sig; ar.raw(dh_sig);

    mintls_error res =
    dh_verify(
        raw_dh_params,      // (I) DH Params
        dh_sig,             // (I) Signature Block
        kex_method,         // (I) Key Exchange Method
        client_random,      // (I) Client Random
        server_random,      // (I) Server Random
        crt_sig_algo,       // (I) Signature Algorithm
        crt_sig_key         // (I) Signature Public Key
    );
    if (res != mintls_success)
    {
        return res;
    }

    // Computer the shared secret and our public key
    if (kex_type == ff_dhe)
    {
        tf_debug("[*] DHE nBits=%d", dh_params.p.nbits());

        BigInt b     = BigInt::rand(dh_params.p.nbits());
        BigInt g_b   = BigInt::exp_mod(dh_params.g,b,dh_params.p);
        BigInt g_ab  = BigInt::exp_mod(dh_params.g_a,b,dh_params.p);

        // [1] 8.1.2
        premaster_secret = g_ab.get_binary();
        public_key       = g_b.get_binary();
    }
    else if (kex_type == ecdhe)
    {
        MinTLS_NamedCurve curve = ecdh_params.curve_params.named_curve.underlying();
        if (curve != mintls_secp224r1 && curve != mintls_secp256r1)
        {
            tf_debug("[E] Unsupported elliptic curve %d", curve);
            return mintls_err_illegal_parameter;
        }

        tf_debug("[*] ECDHE curve=%d", curve);
        size_t const scalar_sz = mintls_ecdh_scalar_size(curve);

        // Create random private key
        std::vector<uint8_t> private_key(scalar_sz);
        mintls_random(&private_key[0], private_key.size());

        // Compute public key
        public_key = ecdh_base_scalar_mult(curve, private_key);

        // Compute shared secret
        std::vector<uint8_t> shared_secret = ecdh_scalar_mult(curve, private_key, ecdh_params.ec_point.point.get());

        // Extract the X-Coordinate
        premaster_secret = std::vector<uint8_t>(shared_secret.begin()+1,shared_secret.begin()+1+scalar_sz);
        return mintls_success;
    }
    else
    {
        return mintls_err_illegal_parameter;
    }

    return mintls_success;
}


// [1] 8.1 Expand pre-master secret
void
expand_premaster_secret(
    std::vector<uint8_t> const&     premaster_secret,   // (I) Premaster secret
    PRFMode                         prf_mode,           // (I) PRF mode
    std::vector<uint8_t> const&     client_random,      // (I) Client Random
    std::vector<uint8_t> const&     server_random,      // (I) Server Random
    std::vector<uint8_t>&           master_secret       // (O) Master secret
)
{
    master_secret.clear();

    TLSPRF(
        master_secret,                  // (O) PRF Output
        prf_mode,                       // (I) PRF mode
        48,                             // (I) Number of bytes needed
        premaster_secret,               // (I) Secret
        "master secret",                // (I) Label (null-terminated string)
        client_random+server_random     // (I) Seed
    );
}

// [1] 6.3 Expand master secret into MAC keys and encryption keys
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
)
{
    // Expand into MAC keys and encryption keys [1] 6.3
    PRFMode             prf_mode     = CipherSuites::prf_mode(cipher_suite);
    MACAlgorithm        mac_algo     = CipherSuites::mac_algorithm(cipher_suite);
    MinTLS_Cipher       cipher       = CipherSuites::cipher(cipher_suite);

    size_t const mac_key_sz   = (mac_algo == MACAlgorithms::AEAD) ? 0 : mintls_hash_tag_length(MACAlgorithms::hmac_version(mac_algo));
    size_t const key_sz       = mintls_cipher_key_length(cipher);

    std::vector<uint8_t> key_block;
    TLSPRF(
        key_block,                      // (O) PRF Output
        prf_mode,                       // (I) PRF mode
        mac_key_sz*2+key_sz*2,          // (I) Number of bytes needed
        master_secret,                  // (I) Secret
        "key expansion",                // (I) Label (null-terminated string)
        server_random+client_random     // (I) Seed
    );

    client_mac_key.assign(&key_block[0],&key_block[mac_key_sz]);
    server_mac_key.assign(&key_block[mac_key_sz],&key_block[mac_key_sz*2]);
    client_key.assign(&key_block[mac_key_sz*2],&key_block[mac_key_sz*2+key_sz]);
    server_key.assign(&key_block[mac_key_sz*2+key_sz],&key_block[mac_key_sz*2+key_sz*2]);
}

mintls_error
pubkey_verify(
    std::vector<uint8_t> const&     signature,          // (I) TLS Signature
    std::vector<uint8_t> const&     data,               // (I) Data to be signed
    asn1::AlgorithmIdentifier const&sig_algo,           // (I) Signature Algorithm
    asn1::AlgorithmIdentifier const&pk_algo,            // (I) Public Key Algorithm
    std::vector<uint8_t> const&     key                 // (I) Public Key
)
{
    MinTLS_SignatureAlgorithm algo = mintls_pubkey_algo(sig_algo.oid.to_string().c_str());
    MinTLS_Hash        hash = mintls_pubkey_algo_hash(sig_algo.oid.to_string().c_str());

    // The signature algorithm has to match up with public key algorithm
    if (algo != mintls_pubkey_algo(pk_algo.oid.to_string().c_str()))
    {
        return mintls_err_illegal_parameter;
    }

    if (algo != MinTLS_RSA_PKCS15 || hash == (MinTLS_Hash)0)
    {
        return mintls_err_illegal_parameter;
    }

    return
    mintls_pubkey_verify(
        &signature[0],      // (I) Signature
        signature.size(),   // (I) Signature length
        algo,               // (I) Signature Algorithm
        hash,               // (I) Hash Algorithm
        &data[0],           // (I) Message
        data.size(),        // (I) Message length (bytes)
        &key[0],            // (I) Public Key (Usually ASN.1 Encoded)
        key.size()          // (I) Public Key Length
    );
}
