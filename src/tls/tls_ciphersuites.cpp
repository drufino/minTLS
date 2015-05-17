/*
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#include "tls_ciphersuites.hpp"
#include <stdexcept>

MinTLS_Hash MACAlgorithms::hmac_version(MACAlgorithm mac_algo)
{
    switch (mac_algo.underlying())
    {
    case HMAC_SHA1:
        return MinTLS_SHA_160;
    case HMAC_SHA224:
        return MinTLS_SHA_224;
    case HMAC_SHA256:
        return MinTLS_SHA_256;
    case HMAC_SHA384:
        return MinTLS_SHA_384;
    case HMAC_SHA512:
        return MinTLS_SHA_512;
    default:
        throw std::runtime_error("MAC algorithm is not HMAC");
    }
}

bool CipherSuites::recognised(CipherSuite code)
{
    switch (code.underlying())
    {
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_ECDHE_RSA_WITH_NULL_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_anon_WITH_NULL_SHA:
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        return true;
    default:
        return false;
    }
}

KexMethod CipherSuites::kex_method(CipherSuite code)
{
    switch (code.underlying())
    {
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_WITH_NULL_SHA256:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
        return KexMethods::RSA;

    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        return KexMethods::DH_RSA;

    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
    case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        return KexMethods::DH_DSS;

    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        return KexMethods::DHE_RSA;

    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        return KexMethods::DHE_DSS;

    case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        return KexMethods::DH_anon;

    case TLS_ECDH_ECDSA_WITH_NULL_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        return KexMethods::ECDH_ECDSA;

    case TLS_ECDH_RSA_WITH_NULL_SHA:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        return KexMethods::ECDH_RSA;

    case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        return KexMethods::ECDHE_ECDSA;

    case TLS_ECDHE_RSA_WITH_NULL_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        return KexMethods::ECDHE_RSA;

    case TLS_ECDH_anon_WITH_NULL_SHA:
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        return KexMethods::ECDH_anon;

    default:
        throw std::runtime_error("unrecognised cipher suite");
    }
}

PRFMode CipherSuites::prf_mode(CipherSuite code)
{
    // XXX - only correct for TLS v1.2
    switch (code.underlying())
    {
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
            return PRFModes::PRF_SHA384;
        default:
            return PRFModes::PRF_SHA256;
    }
}

MinTLS_Hash CipherSuites::hash_algorithm(CipherSuite code)
{
    switch (code.underlying())
    {
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        return MinTLS_SHA_384;
    default:
        return MinTLS_SHA_256;
    }
}

MACAlgorithm CipherSuites::mac_algorithm(CipherSuite code)
{
    switch (code.underlying())
    {
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_ECDSA_WITH_NULL_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_RSA_WITH_NULL_SHA:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_NULL_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_anon_WITH_NULL_SHA:
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        return MACAlgorithms::HMAC_SHA1;
    case TLS_RSA_WITH_NULL_SHA256:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        return MACAlgorithms::HMAC_SHA256;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        return MACAlgorithms::HMAC_SHA384;
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
    case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
    case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        return MACAlgorithms::AEAD;
    default:
        throw std::runtime_error("CipherSuites::mac_algorithm(): unrecognised cipher suite");
    }
}

MinTLS_Cipher CipherSuites::cipher(CipherSuite code)
{
    switch (tls_cipher(code).underlying())
    {
    case TLSCiphers::AES_128:
        return MinTLS_AES_128;
    case TLSCiphers::AES_256:
        return MinTLS_AES_256;
    case TLSCiphers::NullCipher:
    default:
        throw std::runtime_error("Cipher not a block cipher");
    }
}

TLSCipher CipherSuites::tls_cipher(CipherSuite code)
{
    switch (code.underlying())
    {
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_WITH_NULL_SHA256:
    case TLS_ECDH_ECDSA_WITH_NULL_SHA:
    case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
    case TLS_ECDH_RSA_WITH_NULL_SHA:
    case TLS_ECDHE_RSA_WITH_NULL_SHA:
    case TLS_ECDH_anon_WITH_NULL_SHA:
        return TLSCiphers::NullCipher;

    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
    case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
    case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        return TLSCiphers::AES_128;

    case TLS_RSA_WITH_AES_256_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        return TLSCiphers::AES_256;

    default:
        throw std::runtime_error("CipherSuites::cipher(): unrecognised cipher suite");
    }
}

MinTLS_SignatureAlgorithm CipherSuites::sig_algo(TLSSignatureAlgorithm sig_algo)
{
    switch (sig_algo.underlying())
    {
    case TLSSignatureAlgorithms::ANONYMOUS:
        return MinTLS_Anonymous;
    case TLSSignatureAlgorithms::RSA:
        return MinTLS_RSA_PKCS15;
    default:
        throw std::runtime_error("CipherSuites::sig_algorithm(): unrecognised algorithm");
    }
}
