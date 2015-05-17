/* Functionality related to TLS Handshake Protocol
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "tls_handshake.hpp"
#include "tls_ciphersuites.hpp"
#include <cstring>
#include <sstream>
#include "core/tf_debug.hpp"

////////////////////////////////////////////////
//
// TLS Handshake Message
//
TLSHandshakeMsg::TLSHandshakeMsg(Type handshake_type) :
  m_handshake_type(handshake_type)
{
    
}

size_t TLSHandshakeMsg::header_sz(4);

bool
TLSHandshakeMsg::is_valid(Type type)
{
    switch (type)
    {
    case HelloRequest:
    case ClientHello:
    case ServerHello:
    case Certificate:
    case ServerKex:
    case CertificateReq:
    case ServerHelloDone:
    case CertificateVerify:
    case ClientKex:
    case Finished:
        return true;
    default:
        return false;
    }
}
// Read the handshake header
void
TLSHandshakeMsg::read_header(
    uint8_t const *     buf,            // (I) Header (4 bytes)
    Type&               type,           // (O) Type
    size_t&             length          // (O) Length
)
{
    type = (Type)buf[0];
    if (!is_valid(type))
    {
        tf_debug("[E] Invalid handshake type (%d)",type);
        throw TLSException("Invalid handshake type", mintls_err_unexpected_message);
    }

    length  = 0;
    length += buf[1] << 16;
    length += buf[2] << 8;
    length += buf[3];
}

void
TLSHandshakeMsg::write_header(
    std::vector<uint8_t>&       buf,            // (O) Buffer to append to
    Type                        type,           // (I) Handshake type
    size_t                      msg_sz          // (I) Message size
)
{
    oarchive ar(buf);

    // TLS Handshake Header
    ar << type << (uint24_t)msg_sz;
}

void
TLSHandshakeMsg::write_payload(
    std::vector<uint8_t>&       buf         // (O) Buffer to append to
) const
{
    TLSHandshakeMsg::write_header(
        buf,                    // (O) Buffer to append to
        handshake_type(),       // (I) Content Type
        serialize_length(*this) // (I) Message Size
    );

    oarchive ar(buf);
    ar << *this;
}

ContentType
TLSHandshakeMsg::content_type() const
{
    return ContentTypes::Handshake;
}

////////////////////////////////////////////////
//
// TLS Server Hello
//
TLSServerHello::TLSServerHello() :
  TLSHandshakeMsg(ServerHello)
{
}

TLSServerHello::TLSServerHello(
    TLSProtocolVersion const&       version_,
    std::vector<uint8_t> const&     server_random_,
    std::vector<uint8_t> const&     session_,
    CipherSuite                     cipher_,
    uint8_t                         comp_method_
) :
  TLSHandshakeMsg(ServerHello),
  version(version_),
  session(session_),
  cipher(cipher_),
  comp_method(comp_method_)
{
    if (server_random_.size() != 32)
    {
        throw std::runtime_error("TLSServerHello: expected random to be 32 bytes");
    }

    memcpy(random, &server_random_[0],32);
}

// Comparison operator
bool TLSServerHello::operator==(TLSServerHello const& rhs) const
{
    #define cmp(name) name == rhs.name
    return
        cmp(version) &&
        !memcmp(random,rhs.random,32) &&
        cmp(session) &&
        cmp(cipher) &&
        cmp(comp_method) &&
        cmp(extensions);
    #undef cmp
}

void
TLSServerHello::serialize(archive & ar)
{
    ar & version & random & session & cipher & comp_method & extensions;
}

////////////////////////////////////////////////
//
// TLS Client Hello
//
TLSClientHello::TLSClientHello() :
  TLSHandshakeMsg(ClientHello)
{}

    // Initialize a default version
TLSClientHello::TLSClientHello(
    TLSProtocolVersion const&   version_,
    std::vector<uint8_t> const& random_,
    std::vector<CipherSuite> const& cipher_suites_
) :
  TLSHandshakeMsg(ClientHello),
  version(version_),
  comp_methods(1,0)     // NULL compression
{
    suites.get() = cipher_suites_;


    if (random_.size() != 32)
    {
        throw std::runtime_error("TLSClientHello::random must be 32 bytes");
    }

    memcpy(random, &random_[0], 32);
}

void
TLSClientHello::serialize(archive& ar)
{
    ar & version & random & session_id & suites & comp_methods & extensions;
}

void
TLSClientKeyExchange::serialize(archive& ar)
{
    switch (kex_method.underlying())
    {
    case KexMethods::DH_DSS:
    case KexMethods::DHE_DSS:
    case KexMethods::DH_RSA:
    case KexMethods::DHE_RSA:
    case KexMethods::DH_anon:
        ar & dhparams;
        break;
    case KexMethods::ECDH_ECDSA:
    case KexMethods::ECDHE_ECDSA:
    case KexMethods::ECDH_RSA:
    case KexMethods::ECDHE_RSA:
    case KexMethods::ECDH_anon:
        // In this case length must be only 1 octet (per RFC-4492 5.4 ECPoint)
        serialize_vector<uint8_t, uint8_t>(ar,dhparams,false);
        break;
    case KexMethods::RSA:
    default:
        throw TLSException("Unexpected ClientKeyExchange with RSA KexMethod", mintls_err_illegal_parameter);
    }
}

void
TLSFinished::serialize(archive& ar)
{
    ar.raw(verify_data);
}

void
TLSChangeCipherSpec::write_payload(
    std::vector<uint8_t>&   buf          // (O) Buffer to append to
) const
{
    // [1] A.2 change_cipher_spec
    buf.push_back('\x01');
}

ContentType
TLSChangeCipherSpec::content_type() const
{
    return ContentTypes::ChangeCipherSpec;
}

