/* Functionality related to TLS Handshake Protocol
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_handshake_hpp
#define tf_tls_handshake_hpp
#include "core/archive.hpp"
#include <tls/tls_protocol.hpp>
#include <tls/tls_ciphersuites.hpp>
#include <tls/tls_extensions.hpp>
#include "hash.h"
#include <vector>

// Base class for different types of handshake message (RFC-5246)
class TLSHandshakeMsg : public TLSPlaintext
{
public:
    enum Type {
        HelloRequest    =0,
        ClientHello     =1,
        ServerHello     =2,
        Certificate     =11,
        ServerKex       =12,
        CertificateReq  =13,
        ServerHelloDone =14,
        CertificateVerify=15,
        ClientKex       =16,
        Finished        =20
    };

    Type     handshake_type() const { return m_handshake_type; }

    static size_t header_sz;

    static bool is_valid(Type type);

    // Read the handshake header
    static void
    read_header(
        uint8_t const *     buf,            // (I) Header (4 bytes)
        Type&               type,           // (O) Type
        size_t&             length          // (O) Length
    );

    // Write the header
    static void
    write_header(
        std::vector<uint8_t>&       buf,    // (O) Buffer to append to
        Type                        type,   // (I) Handshake Type
        size_t                      msg_sz  // (I) Message size
    );

    // Write the message
    virtual void write_payload(std::vector<uint8_t>& buf) const;

    // Content type
    virtual ContentType content_type() const;

    // Convert to/from wire format (not including handshake header)
    virtual void serialize(archive& ar)=0;

protected:
    TLSHandshakeMsg(Type handshake_type);

private:
    Type   m_handshake_type;
};

typedef TLSHandshakeMsg::Type HandshakeType;
ARCHIVE_ENUM(HandshakeType);

class TLSServerHello : public TLSHandshakeMsg
{
public:
    TLSServerHello();

    TLSServerHello(
        TLSProtocolVersion const&       version,
        std::vector<uint8_t> const&     server_random,
        std::vector<uint8_t> const&     session,
        CipherSuite                     cipher,
        uint8_t                         comp_method
    );

    // Convert to/from wire format (not including handshake header)
    virtual void serialize(archive& ar);

    // Comparison operator
    bool operator==(TLSServerHello const& rhs) const;

    TLSProtocolVersion          version;
    uint8_t                     random[32];
    vararray<uint8_t>::_8       session;
    CipherSuite                 cipher;
    uint8_t                     comp_method;
    vararray<TLSExtension,true>::_16 extensions;
};

// [1] 7.4.1.2
class TLSClientHello : public TLSHandshakeMsg
{
public:
    // Default constructor
    TLSClientHello();

    // Initialize a default version
    TLSClientHello(
        TLSProtocolVersion const&   version_,
        std::vector<uint8_t> const& random_,
        std::vector<CipherSuite> const& cipher_suites_
    );

    // Convert to/from wire format (not including handshake header)
    void serialize(archive& ar);

    // Comparison operator
    bool operator==(TLSClientHello const& rhs) const
    {
        #define cmp(name) name == rhs.name
        return
            cmp(version) &&
            !memcmp(random,rhs.random,32) &&
            cmp(session_id) &&
            cmp(suites) &&
            cmp(comp_methods) &&
            cmp(extensions);
        #undef cmp
    }

    TLSProtocolVersion          version;
    uint8_t                     random[32];
    vararray<uint8_t>::_8       session_id;
    vararray<CipherSuite>::_16  suites;
    vararray<uint8_t>::_8       comp_methods;
    vararray<TLSExtension,true>::_16 extensions;
};

// [1] 7.4.7
class TLSClientKeyExchange : public TLSHandshakeMsg
{
public:
    TLSClientKeyExchange(
        KexMethod                   kex_method_,
        std::vector<uint8_t> const& dhparams_
    ) :
      TLSHandshakeMsg(ClientKex),
      kex_method(kex_method_),
      dhparams(dhparams_)
    {
    }

    TLSClientKeyExchange(
        KexMethod                   kex_method_
    ) :
        TLSHandshakeMsg(ClientKex),
        kex_method(kex_method_)
    {
    }

    // Comparison operator
    bool operator==(TLSClientKeyExchange const& rhs) const
    {
        return dhparams == rhs.dhparams;
    }

    // Convert to/from wire format (not including handshake header)
    void serialize(archive& ar);

    // Key Exchange Method
    KexMethod                   kex_method;

    // Opaque diffie-hellman parameters
    std::vector<uint8_t>        dhparams;

private:
    TLSClientKeyExchange() : TLSHandshakeMsg(ClientKex) {}
};

class TLSFinished : public TLSHandshakeMsg
{
public:
    TLSFinished() : TLSHandshakeMsg(Finished) {}
    TLSFinished(std::vector<uint8_t> const& verify_data_) : TLSHandshakeMsg(Finished), verify_data(verify_data_) {}

    bool operator==(TLSFinished const& rhs) const
    {
        return verify_data == rhs.verify_data;
    }

    // Convert to/from wire format (not including handshake header)
    void serialize(archive& ar);

    std::vector<uint8_t>        verify_data;
};

class TLSChangeCipherSpec : public TLSPlaintext
{
public:
    virtual void
    write_payload(
            std::vector<uint8_t>&   buf          // (O) Buffer to append to
    ) const;

    virtual ContentType content_type() const;
};

#endif /* tf_tls_handshake_hpp */
