/* TLS CipherSuites
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_ciphersuites_hpp
#define tf_tls_ciphersuites_hpp
#include "core/archive.hpp"
#include "hash.h"
#include "core/safe_enum.hpp"
#include "cipher.h"
#include "pubkey.h"

struct KexMethods
{
    enum type
    {
        RSA=0,          // RSA key exchange
        DH_DSS,         // Static Diffie-Hellman (DH) with DSA signature by CA
        DHE_DSS,        // Ephemeral DH with DSA signature from Server Cert
        DH_RSA,         // Static DH with RSA signature by CA
        DHE_RSA,        // Epehemeral DH with DSA signature from Server Cert
        DH_anon,        // DH anonymous

        // RFC 4492 Section 2
        ECDH_ECDSA,     // Fixed ECDH with ECDSA-signed certificates
        ECDHE_ECDSA,    // Ephemeral ECDH with ECDSA signatures
        ECDH_RSA,       // Fixed ECDH with RSA-signed certificates
        ECDHE_RSA,      // Ephemeral ECDH with RSA signatures
        ECDH_anon       // Anonymous ECDH, no signatures
    };
};

// RFC-5246 Defines a Pseudo-Random Function (PRF) Sec 5., based on HMAC
// The PRF may be overridden by the cipher suite.
struct PRFModes
{
    enum type
    {
        PRF_SHA224=3,
        PRF_SHA256=4,
        PRF_SHA384=5,
        PRF_SHA512=6
    };
};

struct MACAlgorithms
{
    // RFC 5246 7.4.1.4.1
    enum type
    {
        NONE=0,
        MD5=1,
        HMAC_SHA1=2,
        HMAC_SHA224=3,
        HMAC_SHA256=4,
        HMAC_SHA384=5,
        HMAC_SHA512=6,
        AEAD=7
    };

    typedef safe_enum<MACAlgorithms> MACAlgorithm;

    static MinTLS_Hash hmac_version(MACAlgorithm mac_algo);
};

struct TLSCiphers
{
    enum type
    {
        NullCipher=0x0,
        AES_128=0x1,
        AES_256=0x3
    };
};

struct TLSSignatureAlgorithms
{
    enum type
    {
        ANONYMOUS=0,
        RSA=1,          // RSASSA-PKCS1-v1_5 RFC3447
        DSA=2,
       ECDSA=3
    };
};


struct CipherSuites;

typedef safe_enum<KexMethods>       KexMethod;
typedef safe_enum<MACAlgorithms>    MACAlgorithm;
typedef safe_enum<TLSSignatureAlgorithms>  TLSSignatureAlgorithm;
typedef safe_enum<TLSCiphers>       TLSCipher;
typedef safe_enum<PRFModes>         PRFMode;

struct CipherSuites
{
    enum type
    {
        // RFC-5246
        // RSA Key Exchange
        TLS_RSA_WITH_NULL_MD5=          0x0001,
        TLS_RSA_WITH_NULL_SHA=          0x0002,
        TLS_RSA_WITH_NULL_SHA256=       0x003B,
/*        TLS_RSA_WITH_RC4_128_MD5=       0x0004,
        TLS_RSA_WITH_RC4_128_SHA=       0x0005,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA=  0x000A,*/
        TLS_RSA_WITH_AES_128_CBC_SHA=   0x002F,
        TLS_RSA_WITH_AES_256_CBC_SHA=   0x0035,
        TLS_RSA_WITH_AES_128_CBC_SHA256=0x003C,
        TLS_RSA_WITH_AES_256_CBC_SHA256=0x003D,

        // Diffie-Hellman Key Exchange
        TLS_DH_DSS_WITH_AES_128_CBC_SHA       = 0x0030,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA       = 0x0031,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA      = 0x0032,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA      = 0x0033,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA       = 0x0036,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA       = 0x0037,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA      = 0x0038,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA      = 0x0039,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = 0x003E,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = 0x003F,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = 0x0040,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = 0x0067,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = 0x0068,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = 0x0069,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = 0x006A,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = 0x006B,

        // RFC-5288, AEAD modes
        TLS_RSA_WITH_AES_128_GCM_SHA256       = 0x009C,
        TLS_RSA_WITH_AES_256_GCM_SHA384       = 0x009D,
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256   = 0x009E,
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384   = 0x009F,
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256    = 0x00A0,
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384    = 0x00A1,
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256   = 0x00A2,
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384   = 0x00A3,
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256    = 0x00A4,
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384    = 0x00A5,
        TLS_DH_anon_WITH_AES_128_GCM_SHA256   = 0x00A6,
        TLS_DH_anon_WITH_AES_256_GCM_SHA384   = 0x00A7,

        // RFC-4492 Section 6, ECC modes
        TLS_ECDH_ECDSA_WITH_NULL_SHA           = 0xC001,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    = 0xC004,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    = 0xC005,
        TLS_ECDHE_ECDSA_WITH_NULL_SHA          = 0xC006,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   = 0xC009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   = 0xC00A,
        TLS_ECDH_RSA_WITH_NULL_SHA             = 0xC00B,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA      = 0xC00E,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA      = 0xC00F,
        TLS_ECDHE_RSA_WITH_NULL_SHA            = 0xC010,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     = 0xC013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     = 0xC014,
        TLS_ECDH_anon_WITH_NULL_SHA            = 0xC015,
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA     = 0xC018,
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA     = 0xC019,

        // RFC-5289 Section 3.1 ECC with HMAC SHA-256
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  = 0xC023,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  = 0xC024,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256   = 0xC025,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384   = 0xC026,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    = 0xC027,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    = 0xC028,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256     = 0xC029,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384     = 0xC02A
    };

    typedef safe_enum<CipherSuites>     CipherSuite;
    static bool            recognised(CipherSuite code);
    static KexMethod       kex_method(CipherSuite code);
    static TLSCipher       tls_cipher(CipherSuite code);
    static MinTLS_Cipher   cipher(CipherSuite code);
    static PRFMode         prf_mode(CipherSuite code);
    static MACAlgorithm    mac_algorithm(CipherSuite code);

    // For use in Finished methods (rfc-5246 7.4.9)
    static MinTLS_Hash     hash_algorithm(CipherSuite code);

    static MinTLS_SignatureAlgorithm sig_algo(TLSSignatureAlgorithm sig_algo);
};


typedef safe_enum<CipherSuites>     CipherSuite;

ARCHIVE_SAFE_ENUM(MACAlgorithm);
ARCHIVE_SAFE_ENUM(TLSSignatureAlgorithm);
ARCHIVE_SAFE_ENUM_16(CipherSuite);
ARCHIVE_ENUM(MinTLS_Hash);

#endif
