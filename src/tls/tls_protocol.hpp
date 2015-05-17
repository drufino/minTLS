/* Functionality related to TLS Record Protocol
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_protocol_hpp
#define tf_tls_protocol_hpp
#include <tls_api.h>
#include "core/archive.hpp"
#include <tls/tls_ciphersuites.hpp>
#include <string>

// TLS Record Protocol has four types of messages 
// RFC-5246 A.1
struct ContentTypes
{
    enum type
    {
        UnknownRecord   =0,
        ChangeCipherSpec=20,
        Alert           =21,
        Handshake       =22,
        ApplicationData =23
    };
};

typedef ContentTypes::type ContentType;
ARCHIVE_ENUM(ContentType);

// Exceptions
class TLSException : public std::exception
{
public:
    TLSException(const char *msg, enum mintls_error err) :
    m_msg(msg), m_err(err) {}

    enum mintls_error err() const { return m_err; }
    const char*  msg() const { return m_msg; }
    virtual const char*  what() const throw() { return m_msg; }

private:
    const char *m_msg;
    enum mintls_error   m_err;
};

// TLS Protocol Version
class TLSProtocolVersion
{
public:
    TLSProtocolVersion(uint8_t major_version_=0x3, uint8_t minor_version_=0x3) :
      major_version(major_version_),
      minor_version(minor_version_)
    {}

    uint8_t     major_version;
    uint8_t     minor_version;

    // Is valid ?
    bool is_valid() const
    {
        return major_version == 0x3 && minor_version <= 0x3 && minor_version >= 0x1;
    }

    // Equality operators
    bool operator==(TLSProtocolVersion const& rhs) const
    {
        return major_version == rhs.major_version && minor_version == rhs.minor_version;
    }

    bool operator!=(TLSProtocolVersion const & rhs) const
    {
        return !(*this == rhs);
    }

    // Serialize into the wire format for TLS protocol
    void serialize(archive& ar)
    {
        ar & major_version & minor_version;
    }
};

// Interface class for converting in-memory representation of TLS Records to 
// the wire format for TLS Protocol. NB excludes the Record Header.
class TLSPlaintext
{
public:
    // Append the plaintext payload of a TLS Record to a buffer
    virtual void
    write_payload(
            std::vector<uint8_t>&   buf          // (O) Buffer to append to
    ) const = 0;


    // Return the Content Tpye
    virtual ContentType content_type() const = 0;
};

// Utility functions for reading and writing TLS records to/from the wire
class TLSRecord
{
public:
    // Size of a TLS Record Header (5)
    static size_t header_sz;

    // Parse a TLS Record Header, with error checking
    static mintls_error
    read_header(
        std::vector<uint8_t> const& buf,        // (I) Buffer
        ContentType&                type,       // (O) Type
        TLSProtocolVersion&         version,    // (O) Version
        size_t &                    record_sz   // (O) Record size (excluding header)
    ) throw();

    // Write out a TLS Record Header
    static mintls_error
    write_header(
        uint8_t *                   buf,        // (O) Buffer to write to
        ContentType                 type,       // (I) Type
        TLSProtocolVersion const&   version,    // (I) Version
        size_t                      msg_sz      // (I) Message Size (excluding record header)
    ) throw();

    // Write out a TLS Record Header
    static mintls_error
    write_header(
        std::vector<uint8_t>&       buf,        // (O) Buffer to append to
        ContentType                 type,       // (I) Type
        TLSProtocolVersion const&   version,    // (I) Version
        size_t                      msg_sz      // (I) Message Size (excluding record header)
    ) throw();

    // Write a TLS Record, including the header
    static mintls_error
    write_plaintext_record(
        std::vector<uint8_t>&       buf,        // (O) Buffer to append to
        TLSProtocolVersion const&   version,    // (I) Version
        TLSPlaintext const&         payload     // (I) Payload
    );

    // Write an encrypted TLS Record, including the header
    static mintls_error
    write_encrypted_record(
        std::vector<uint8_t>&       buf,        // (O) Buffer to append to
        uint64_t                    seq_num,    // (I) Sequence Number
        ContentType                 type,       // (I) Content Type
        TLSProtocolVersion const&   version,    // (I) Version
        CipherSuite                 cipher,     // (I) Cipher Suite
        std::vector<uint8_t> const& IV,         // (I) IV
        std::vector<uint8_t> const& key,        // (I) Key
        std::vector<uint8_t> const& mac_key,    // (I) MAC key
        std::vector<uint8_t> const& plaintext,  // (I) plaintext record (excluding header)
        std::vector<uint8_t>*       padding_override=0     // (I) Optional padding, used for testing purposes
    ) throw();

    // Write out an encrypted record (block-cipher only) including header
    // Encrypt according to [1] 6.2.3.2
    static mintls_error
    write_encrypted_record(
        std::vector<uint8_t>&       buf,        // (O) Buffer to append to
        uint64_t                    seq_num,    // (I) Sequence Number
        ContentType const           type,       // (I) Content Type
        TLSProtocolVersion const&   version,    // (I) Version
        CipherSuite                 cipher,     // (I) Cipher Suite
        std::vector<uint8_t> const& key,        // (I) Key
        std::vector<uint8_t> const& mac_key,    // (I) MAC key
        std::vector<uint8_t> const& payload     // (I) Payload
    ) throw();

    static void
    calculate_record_mac(
        uint8_t *                   mac,        // (O) MAC
        uint64_t const              seq_num,    // (I) Sequence number
        ContentType const           type,       // (I) Content type
        TLSProtocolVersion const&   version,    // (I) Version
        std::vector<uint8_t> const& mac_key,    // (I) MAC Key
        MinTLS_Hash                 hmac,       // (I) HMAC version
        uint8_t const *             plaintext,  // (I) Plaintext
        size_t const                plaintext_sz// (I) Plaintext size
    ) throw();


    static mintls_error
    decrypt_record_payload(
        std::vector<uint8_t>&       pt,         // (O) Unencrypted record payload
        uint64_t                    seq_num,    // (I) Sequence Number
        ContentType                 type,       // (I) Content type
        TLSProtocolVersion const&   version,    // (I) Version
        CipherSuite                 cipher,     // (I) Cipher Suite
        std::vector<uint8_t> const& key,        // (I) Key
        std::vector<uint8_t> const& mac_key,    // (I) MAC key
        uint8_t const *             payload,    // (I) Payload
        size_t const                payload_sz  // (I) Payload size
    ) throw();

    static mintls_error
    decrypt_record(
        std::vector<uint8_t>&       payload,    // (O) Unencrypted record
        uint64_t                    seq_num,    // (I) Sequence Number
        ContentType&                type,       // (O) Content type
        TLSProtocolVersion const&   version,    // (I) Expected Version
        CipherSuite                 cipher,     // (I) Cipher Suite
        std::vector<uint8_t> const& key,        // (I) Key
        std::vector<uint8_t> const& mac_key,    // (I) MAC key
        std::vector<uint8_t> const& record      // (I) Encrypted record
    ) throw();
};
#endif /* tf_tls_protocol_hpp */
