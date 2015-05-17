/* Functionality related to TLS Record Protocol
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "tls_protocol.hpp"
#include "core/archive.hpp"
#include "cipher.h"
#include "hmac.h"
#include "random.h"
#include "core/tf_debug.hpp"
#include <iostream>
#include "core/portability.h"

// RFC-5246 6.2
#define MAX_RECORD_LENGTH (0x4000)

void cipher_do(
    mintls_cipher_ctx           ctx,
    std::vector<uint8_t>&       output,
    std::vector<uint8_t> const& A, 
    std::vector<uint8_t> const& B,
    std::vector<uint8_t> const& C
) throw()
{
    // Total plaintext size
    size_t const total_sz = A.size() + B.size() + C.size();

    // Make space for the output
    output.resize(output.size() + total_sz);

    uint8_t *ptr = &output[output.size() - total_sz];
    #define update(x) mintls_cipher_do_partial(ctx, &x[0], x.size(), &ptr);
    update(A);
    update(B);
    update(C);
    #undef update
}
size_t TLSRecord::header_sz(5);

mintls_error
TLSRecord::read_header(
    std::vector<uint8_t> const& buf,        // (I) Buffer
    ContentType&                type,       // (O) Type
    TLSProtocolVersion&         version,    // (O) Version
    size_t &                    msg_sz      // (O) Message size
) throw()
{
    // Initialize to sensible values
    type    = ContentTypes::UnknownRecord;
    msg_sz  = 0;
    version = TLSProtocolVersion();

    if (buf.size() < TLSRecord::header_sz)
    {
        return mintls_err_decode_error;
    }

    iarchive ar(&buf[0], buf.size());

    ContentType             type_;
    TLSProtocolVersion      version_;
    uint16_t                length_;

    ar & type_ & version_ & length_;

    // Check the ContentType
    switch (type_)
    {
    case ContentTypes::ChangeCipherSpec:
    case ContentTypes::Alert:
    case ContentTypes::Handshake:
    case ContentTypes::ApplicationData:
        break;
    default:
        return mintls_err_unexpected_message;
    }

    if (!version_.is_valid())
    {
        return mintls_err_unexpected_message;
    }


    if (length_ > MAX_RECORD_LENGTH)
    {
        return mintls_err_record_overflow;
    }

    type    = type_;
    version = version_;
    msg_sz  = (size_t)length_;

    return mintls_success;
}

// Write out a TLS Record Header
mintls_error
TLSRecord::write_header(
    uint8_t *                   buf,        // (O) Buffer to write to
    ContentType                 type,       // (I) Type
    TLSProtocolVersion const&   version,    // (I) Version
    size_t                      msg_sz      // (I) Message Size (excluding record header)
) throw()
{
    uint16_t record_length = msg_sz;

    // Check overflow or underflow
    if ((size_t)record_length < msg_sz || record_length > MAX_RECORD_LENGTH)
    {
        return mintls_err_record_overflow;
    }

    buf[0] = (uint8_t)type;
    buf[1] = version.major_version;
    buf[2] = version.minor_version;
    buf[3] = (record_length & 0xff00) >> 8;
    buf[4] = (record_length & 0x00ff);
    //ar << type << version << record_length;

    return mintls_success;
}

mintls_error
TLSRecord::write_header(
    std::vector<uint8_t>&       buf,        // (O) Buffer to append to
    ContentType                 type,       // (I) Type
    TLSProtocolVersion const&   version,    // (I) Version
    size_t                      msg_sz      // (I) Message Size
) throw()
{
    buf.resize(buf.size()+TLSRecord::header_sz);
    mintls_error err = TLSRecord::write_header(&buf[buf.size()-TLSRecord::header_sz],type,version,msg_sz);
    if (err != mintls_success)
    {
        buf.resize(buf.size()-TLSRecord::header_sz);
    }
    return err;
}

mintls_error
TLSRecord::write_plaintext_record(
    std::vector<uint8_t>&       buf,        // (O) Buffer to append to
    TLSProtocolVersion const&   version,    // (I) Version
    TLSPlaintext const&         payload     // (I) Payload
)
{
    buf.resize(buf.size() + TLSRecord::header_sz);

    size_t const old_sz = buf.size();

    // Write the content
    payload.write_payload(buf);

    size_t const payload_sz = buf.size() - old_sz;

    tf_debug("[*]   Sending plaintext record [payload_sz=%d]", payload_sz);

    // Write the header
    ContentType type = payload.content_type();

    mintls_error err = TLSRecord::write_header(&buf[old_sz - TLSRecord::header_sz], type, version, payload_sz);
    if (err == mintls_success)
    {
        return mintls_success;
    }
    else
    {
        // Return to its original state!
        buf.resize(old_sz - TLSRecord::header_sz);
        return err;
    }
}

void
TLSRecord::calculate_record_mac(
    uint8_t *                   mac,        // (O) MAC
    uint64_t const              seq_num,    // (I) Sequence number
    ContentType const           type,       // (I) Content type
    TLSProtocolVersion const&   version,    // (I) Version
    std::vector<uint8_t> const& mac_key,    // (I) MAC Key
    MinTLS_Hash                 hmac_version,// (I) HMAC version
    uint8_t const *             plaintext,  // (I) Plaintext
    size_t const                plaintext_sz// (I) Plaintext size
) throw()
{
    // Space for the MAC
    size_t const        mac_sz      = mintls_hash_tag_length(hmac_version);

    uint8_t seq_num_buf[8];
    seq_num_buf[7] = seq_num & 0x00ff;
    seq_num_buf[6] = (uint8_t)((seq_num & 0xff00) >> 8);
	seq_num_buf[5] = (uint8_t)((seq_num & 0xff0000) >> 16);
	seq_num_buf[4] = (uint8_t)((seq_num & 0xff000000) >> 24);
	seq_num_buf[3] = (uint8_t)((seq_num & 0xff00000000) >> 32);
	seq_num_buf[2] = (uint8_t)((seq_num & 0xff0000000000) >> 40);
	seq_num_buf[1] = (uint8_t)((seq_num & 0xff000000000000) >> 48);
	seq_num_buf[0] = (uint8_t)((seq_num & 0xff00000000000000) >> 56);

    // MAC the record header
	VLA(uint8_t, TLSCompressedHeader, TLSRecord::header_sz);

    TLSRecord::write_header(&TLSCompressedHeader[0], type, version, plaintext_sz);

    mintls_hmac_context mac_ctx;
    mintls_hmac_init(&mac_ctx, hmac_version, mac_sz, &mac_key[0], mac_key.size());

    // MAC Seq+Header+Plaintext
    mintls_hmac_update(&mac_ctx, seq_num_buf, 8);
    mintls_hmac_update(&mac_ctx, &TLSCompressedHeader[0], TLSRecord::header_sz);
    mintls_hmac_update(&mac_ctx, plaintext, plaintext_sz);

    // Append the MAC
    mintls_hmac_finish(&mac_ctx,mac);
}

mintls_error
TLSRecord::decrypt_record_payload(
    std::vector<uint8_t>&       pt,         // (O) Unencrypted record
    uint64_t                    seq_num,    // (I) Sequence Number
    ContentType                 type,       // (I) Content type
    TLSProtocolVersion const&   version,    // (I) Version
    CipherSuite                 cipher_suite,     // (I) Cipher
    std::vector<uint8_t> const& key,        // (I) Key
    std::vector<uint8_t> const& mac_key,    // (I) MAC key
    uint8_t const *             payload,    // (I) Payload
    size_t const                payload_sz  // (I) Payload size
) throw()
{
    // Decrypt according to [1] 6.2.3.2
    MinTLS_Cipher       cipher      = CipherSuites::cipher(cipher_suite);
    MinTLS_CipherMode   mode        = MinTLS_CBC;
    uint16_t            block_sz    = mintls_cipher_block_length(cipher,mode);
    MACAlgorithm        mac_algo    = CipherSuites::mac_algorithm(cipher_suite);
    MinTLS_Hash         hmac_version= MACAlgorithms::hmac_version(mac_algo);

    // Space for the MAC
    size_t const        mac_sz      = mintls_hash_tag_length(hmac_version);

    if (key.size() != mintls_cipher_key_length(cipher))
    {
        return mintls_err_internal_error;
    }

    // Must have at least one IV block and >=1 ciphertext block
    if (payload_sz < block_sz*2 || ((payload_sz % block_sz) != 0))
    {
        return mintls_err_decode_error;
    }

    // IV
    uint8_t const * IV = payload;
    // Encrypted block
    uint8_t const * ct = payload + block_sz;
    size_t const    ct_sz = payload_sz - block_sz;

    pt.assign(ct_sz,0);

    mintls_cipher_ctx ctx =
    mintls_cipher_new(
        cipher,         // (I) Underlying Block Cipher
        mode,           // (I) Underlying Mode
        MinTLS_Decrypt, // (I) Direction
        &key[0],        // (I) Key
        IV              // (I) Initialization vector (if required for CBC)
    );

    mintls_cipher_do(
        ctx,        // (I) Context
        ct,         // (I) Input
        ct_sz,      // (I) Size (Assumed to be multiple of block size)
        &pt[0]      // (O) Output
    );

    mintls_cipher_destroy(ctx);

    // Check padding and MAC.
    // XXX MAKE CONSTANT TIME XXX
    //    https://www.imperialviolet.org/2013/02/04/luckythirteen.html
    size_t padding = pt[pt.size()-1]; padding++;
    if (pt.size() < padding + mac_sz)
    {
        pt.clear();
        return mintls_err_bad_record_mac;
    }

    // Check padding is filled with padding value
    for (unsigned i = 0; i < padding; ++i)
    {
        if (pt[pt.size()-1-i] != (uint8_t)(padding-1))
        {
            pt.clear();
            return mintls_err_bad_record_mac;
        }
    }

    size_t const pt_sz = pt.size() - mac_sz - padding;

    std::vector<uint8_t> MAC(mac_sz);
    TLSRecord::calculate_record_mac(
        &MAC[0],            // (O) MAC
        seq_num,            // (I) Sequence number
        type,               // (I) Content type
        version,            // (I) Version
        mac_key,            // (I) MAC Key
        hmac_version,       // (I) HMAC Version
        &pt[0],             // (I) Plaintext
        pt_sz               // (I) Plaintext size
    );

    // Check the MACs
    if (memcmp(&MAC[0], &pt[pt_sz], mac_sz) != 0)
    {
        pt.clear();
        return mintls_err_bad_record_mac;
    }

    // Remove the MAC and padding
    pt.resize(pt_sz);

    return mintls_success;
}

mintls_error
TLSRecord::decrypt_record(
    std::vector<uint8_t>&       pt,         // (O) Unencrypted record
    uint64_t                    seq_num,    // (I) Sequence Number
    ContentType&                type,       // (O) Content type
    TLSProtocolVersion const&   version,    // (I) Version
    CipherSuite                 cipher,     // (I) Cipher
    std::vector<uint8_t> const& key,        // (I) Key
    std::vector<uint8_t> const& mac_key,    // (I) MAC key
    std::vector<uint8_t> const& record      // (I) Encrypted record
) throw()
{
    if (record.size() < TLSRecord::header_sz)
    {
        return mintls_err_decode_error;
    }

    // Read the protocol header
    TLSProtocolVersion  this_version;
    size_t              record_sz;

    mintls_error err =
    TLSRecord::read_header(
        record,         // (I) Buffer
        type,           // (O) Type
        this_version,   // (O) Version
        record_sz       // (O) Record size (excluding header)
    );

    if (err != mintls_success)
    {
        return err;
    }

    // Check record size
    if (record_sz + TLSRecord::header_sz != record.size())
    {
        return mintls_err_decode_error;
    }

    // Check record size
    if (this_version != version)
    {
        return mintls_err_decode_error;
    }

    return
    TLSRecord::decrypt_record_payload(
        pt,         // (O) Unencrypted record
        seq_num,    // (I) Sequence Number
        type,       // (I) Type
        version,    // (I) Version
        cipher,     // (I) Cipher
        key,        // (I) Key
        mac_key,    // (I) MAC key
        &record[TLSRecord::header_sz],    // (I) Payload
        record_sz // (I) Payload size
    );
}

mintls_error
TLSRecord::write_encrypted_record(
    std::vector<uint8_t>&       buf,        // (O) Buffer to append to
    uint64_t                    seq_num,    // (I) Sequence Number
    ContentType                 type,       // (I) Content Type
    TLSProtocolVersion const&   version,    // (I) Version
    CipherSuite                 cipher_suite,// (I) Cipher Suite
    std::vector<uint8_t> const& IV,         // (I) IV
    std::vector<uint8_t> const& key,        // (I) Key
    std::vector<uint8_t> const& mac_key,    // (I) MAC key
    std::vector<uint8_t> const& plaintext,  // (I/O) plaintext
    std::vector<uint8_t>*       padding_override     // (I) Input optional padding
) throw()
{
    // Encrypt according to [1] 6.2.3.2
    MinTLS_Cipher       cipher      = CipherSuites::cipher(cipher_suite);
    MinTLS_CipherMode   mode        = MinTLS_CBC;
    uint16_t            block_sz    = mintls_cipher_block_length(cipher,mode);
    MACAlgorithm        mac_algo    = CipherSuites::mac_algorithm(cipher_suite);
    MinTLS_Hash         hmac_version= MACAlgorithms::hmac_version(mac_algo);

    // Check key size
    if (key.size() != mintls_cipher_key_length(cipher))
    {
        return mintls_err_internal_error;
    }

    // Check IV size
    if (IV.size() != block_sz)
    {
        return mintls_err_internal_error;
    }

    // Space for the MAC
    size_t const        mac_sz      = mintls_hash_tag_length(hmac_version);

    // Work out the padding
    uint8_t padding_sz = block_sz - ((mac_sz + plaintext.size()) % block_sz);

    size_t const total_sz = IV.size() + plaintext.size() + mac_sz + padding_sz;

    // Write the (unencrypted) record header
    TLSRecord::write_header(
        buf,            // (O) Buffer to append to
        type,           // (I) Content Type
        version,        // (I) Version
        total_sz        // (I) Size of the message
    );

    //tf_debug("[*]   Sending encrypted record [IV=%d,pt=%d,mac=%d,padding=%d,total=%d]", IV.size(),plaintext.size(),mac_sz,padding,total_sz);

    // Generate the Plaintext MAC first [1] 6.2.3.1 and append to the packet
    std::vector<uint8_t> MAC(mac_sz);
    TLSRecord::calculate_record_mac(
        &MAC[0],            // (O) MAC
        seq_num,            // (I) Sequence number
        type,               // (I) Content type
        version,            // (I) Version
        mac_key,            // (I) MAC Key
        hmac_version,       // (I) HMAC Version
        &plaintext[0],      // (I) Plaintext
        plaintext.size()    // (I) Plaintext size
    );

    // Insert the padding
    std::vector<uint8_t> padding(padding_sz, padding_sz - 1);
    if (padding_override)
    {
        if (padding_override->size() != padding_sz)
        {
            return mintls_err_internal_error;
        }
        else
        {
            padding = *padding_override;
        }
    }

    // Write out the IV
    buf.insert(buf.end(), IV.begin(), IV.end());

    mintls_cipher_ctx ctx =
    mintls_cipher_new(
        cipher,         // (I) Underlying Block Cipher
        mode,           // (I) Underlying Mode
        MinTLS_Encrypt, // (I) Encryption (>=0) Decryption (<0)
        &key[0],        // (I) Key
        &IV[0]          // (I) Initialization vector (if required for CBC)
    );

    cipher_do(
        ctx,            // (I) Context
        buf,            // (O) Output
        plaintext,      // (I) Plaintext
        MAC,            // (I) Plaintext
        padding         // (I) Plaintext
    );

    mintls_cipher_destroy(ctx);

    return mintls_success;
}

// Write out an encrypted record (block-cipher only)
// Encrypt according to [1] 6.2.3.2
mintls_error
TLSRecord::write_encrypted_record(
    std::vector<uint8_t>&       buf,        // (O) Buffer to append to
    uint64_t                    seq_num,    // (I) Sequence Number
    ContentType const           type,       // (I) Content type
    TLSProtocolVersion const&   version,    // (I) Version
    CipherSuite                 cipher_suite,// (I) Cipher Suite
    std::vector<uint8_t> const& key,        // (I) Key
    std::vector<uint8_t> const& mac_key,    // (I) MAC key
    std::vector<uint8_t> const& payload     // (I) Payload
) throw()
{
    // Encrypt according to [1] 6.2.3.2
    MinTLS_Cipher       cipher      = CipherSuites::cipher(cipher_suite);
    MinTLS_CipherMode   mode        = MinTLS_CBC;
    uint16_t            block_sz    = mintls_cipher_block_length(cipher,mode);

    // Create random IV
    std::vector<uint8_t> IV(block_sz, 0);
    mintls_random(&IV[0],IV.size());

    return
    TLSRecord::write_encrypted_record(
        buf,        // (O) Buffer to append to
        seq_num,    // (I) Sequence Number
        type,       // (I) Content Type
        version,    // (I) Version
        cipher_suite,// (I) Cipher Suite
        IV,         // (I) IV
        key,        // (I) Key
        mac_key,    // (I) MAC key
        payload     // (I/O) plaintext
    );
}
