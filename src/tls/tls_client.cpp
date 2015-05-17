/* TLS Client Session
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "tls_client.hpp"
#include "tls_certificate.hpp"
#include "tls_primitives.hpp"
#include "tls_ecc.hpp"
#include "random.h"
#include <iostream>
#include "hash.h"
#include "hmac.h"
#include <cstring>
#include <stdexcept>
#include <typeinfo>
#include <functional>
#include "core/tf_debug.hpp"

TLSSession::TLSSession(Side side) :
  m_side(side),
  m_protocol_state(Handshaking),
  m_handshake_yield_point(0),
  m_state()
{
    switch (m_side)
    {
    case Client:
    {
        // [1] 7.4.1.2
        m_state.client_random.assign(32, 0);
        mintls_random(&m_state.client_random[0], 32);


        std::vector<CipherSuite> cipher_suites;
        cipher_suites.push_back(CipherSuites::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cipher_suites.push_back(CipherSuites::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        cipher_suites.push_back(CipherSuites::TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        cipher_suites.push_back(CipherSuites::TLS_DHE_RSA_WITH_AES_256_CBC_SHA);


        // Send the Client Hello
        TLSClientHello client_hello(m_state.version, m_state.client_random, cipher_suites);

        // Indicate we support P-224
        std::vector<TLSNamedCurve> curves;
        curves.push_back(mintls_secp224r1);
        curves.push_back(mintls_secp256r1);
        client_hello.extensions.push_back(
            TLSExtension(std::make_shared<TLSSupportedEllipticCurves>(curves))
        );


        mintls_error err = send_msg(client_hello);
        if (err != mintls_success)
        {
            throw TLSException("TLSClientHello", err);
        }
        break;
    }
    case Server:
        break;
    default:
        break;
    }
}

mintls_error
TLSSession::set_config(TLSConfig const& config)
{
    if (m_protocol_state != Disconnected)
    {
        return mintls_failed;
    }
    else
    {
        m_config = config;
        return mintls_success;
    }
}

mintls_error
TLSSession::process_server_hello_impl(
    TLSServerHello const&   server_hello,       // (I) ServerHello message
    TLSState&               state,              // (I/O) State governing the Session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    // Don't allow version downgrades, NB not rfc compliant, and breaks compatibility with deployed systems
    if (server_hello.version != state.version)
    {
        tf_debug("[E] Received ServerHello version mismatch");
        return mintls_err_protocol_version;
    }

    // Only allow NULL compression
    if (server_hello.comp_method != 0x0)
    {
        tf_debug("[E] Received ServerHello compression mismatch");
        return mintls_err_handshake_failed;
    }

    // Get the state
    state.server_random.assign(server_hello.random,server_hello.random+sizeof(server_hello.random));
    state.comp_method   = server_hello.comp_method;
    state.cipher_suite  = server_hello.cipher;

    if (!CipherSuites::recognised(state.cipher_suite))
    {
        tf_debug("[*] Unrecognised Cipher=0x%lx", state.cipher_suite.underlying());
        return mintls_err_handshake_failed;
    }
    tf_debug("[*] Received ServerHello Cipher=0x%lx", state.cipher_suite.underlying());
    for (unsigned iExt = 0; iExt < server_hello.extensions.size(); ++iExt)
    {
        TLSExtension const& ext = server_hello.extensions[iExt];
        if (TLSSupportedEllipticCurves const *tls_ecc = ext.get<TLSSupportedEllipticCurves>())
        {
            for (unsigned i = 0; i < tls_ecc->m_curves.size(); ++i)
            {
                tf_debug("[*] Supported Elliptic Curve: %d", tls_ecc->m_curves[i].underlying());
            }
        }
    }
    return mintls_success;
}

mintls_error
TLSSession::process_server_hello(
    iarchive&               ar,                 // (I) ServerHello message
    TLSState&               state,              // (I/O) State governing the Session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    TLSServerHello server_hello;
    ar & server_hello;

    return process_server_hello_impl(server_hello, state, send_msg);
}

mintls_error
TLSSession::process_certificate(
    iarchive&               ar,                 // (I) Certificates message
    TLSState&               state,              // (I/O) State governing the Session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    tf_debug("[*] Received Certificate message");
    ar & state.certificates;
    tf_debug("[*] Got %zu certificates.", state.certificates.size());
    std::string reason;
    if (!verify_certificate_chain(state.certificates, asn1::Time::now(), reason))
    {
        tf_debug("[E] Certificate verification failed: '%s'", reason.c_str());
        return mintls_err_bad_certificate;
    }
    else
    {
        tf_debug("[*] Successfully verified certificate chain");
    }
    return mintls_success;
}

mintls_error
TLSSession::process_server_kex(
    iarchive&               ar,                 // (I) ServerKeyExchanage message
    TLSState&               state,              // (I/O) State governing the session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    KexMethod kex_method = CipherSuites::kex_method(state.cipher_suite);
    if (kex_method == KexMethods::DHE_RSA || kex_method == KexMethods::DH_anon ||
        kex_method == KexMethods::ECDHE_RSA)
    {
        tf_debug("[*] Received ServerKex");

        // Perform the key agreement
        std::vector<uint8_t> premaster_secret;
        std::vector<uint8_t> sig_key;
        asn1::AlgorithmIdentifier sig_algo;
        if (state.certificates.size() > 0)
        {
            sig_key = state.certificates.front().public_key;
            sig_algo = state.certificates.front().pk_algo;
        }

        std::vector<uint8_t> server_kex_msg; ar.raw(server_kex_msg);
        mintls_error dh_err =
        dh_key_agreement(
            server_kex_msg,
            kex_method,
            state.client_random,
            state.server_random,
            sig_algo,
            sig_key,
            state.public_key,
            premaster_secret
        );

        if (dh_err != mintls_success)
        {
            tf_debug("[E] Diffie-Hellman key exchange failed.");
            return dh_err;
        }

        tf_dbg("[*] PREMASTER SECRET: " << to_hex(premaster_secret));
        tf_dbg("[*] CLIENT RANDOM:    " << to_hex(state.client_random));
        tf_dbg("[*] SERVER RANDOM:    " << to_hex(state.server_random));

        PRFMode            prf_mode = CipherSuites::prf_mode(state.cipher_suite);

        // Compute the master secret and get the encryption keys
        expand_premaster_secret(
            premaster_secret,           // (I) Premaster secret
            prf_mode,                   // (I) PRF Mode
            state.client_random,        // (I) Client Random
            state.server_random,        // (I) Server Random
            state.master_secret         // (O) Master secret
        );

        tf_dbg("[*] MASTER SECRET:    " << to_hex(state.master_secret));

        expand_master_secret(
            state.master_secret,        // (I) Master secret
            state.client_random,        // (I) Client Random
            state.server_random,        // (I) Server Random
            state.cipher_suite,         // (I) MAC Algorithm
            state.client_mac_key,       // (O) Client MAC key
            state.server_mac_key,       // (O) Server MAC key
            state.client_key,           // (O) Client key
            state.server_key            // (O) Server key
        );

        tf_dbg("[*] CLIENT KEY:       " << to_hex(state.client_key));
        tf_dbg("[*] CLIENT MAC KEY:   " << to_hex(state.client_mac_key));
    }
    else
    {
        tf_debug("[*] Unexpected ServerKex message");
        return mintls_err_unexpected_message;
    }
    return mintls_success;
}

mintls_error
TLSSession::handshake_unsupported(
    iarchive&               ar,                 // (I) Handshake message
    TLSState&               state,              // (I/O) State governing the session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    tf_debug("[E] Received CertificateReq");
    // Don't support client authentication
    return mintls_err_handshake_failed;
}

mintls_error
TLSSession::process_server_hello_done(
    iarchive&               ar,                 // (I) ServerHelloDone message
    TLSState&               state,              // (I/O) State governing the session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    tf_debug("[*] Received ServerHelloDone");

    // Send ClientKeyExchange
    tf_debug("[*] Sending ClientKeyExchange");
    KexMethod const kex_method = CipherSuites::kex_method(state.cipher_suite);
    mintls_error err = send_msg(TLSClientKeyExchange(kex_method, state.public_key));
    if (err != mintls_success)
    {
        return err;
    }

    // Followed by ChangeCipherSpec
    tf_debug("[*] Sending ChangeCipherSpec");
    err = send_msg(TLSChangeCipherSpec());
    if (err != mintls_success)
    {
        return err;
    }

    // Calculate hash of the handshake messages ([1] 7.4.9) to be sent with the finished message
    std::vector<uint8_t> verify_data;
    calculate_finished_data(
        verify_data,                // (O) Verify Data
        state.master_secret,        // (I) Master Secret
        state.handshake_data,       // (I) Total handshake data
        state.cipher_suite,         // (I) Cipher
        "client finished"           // (I) Label
    );

    state.client_encrypting = true;
    state.client_seq_num = 0;
    state.server_seq_num = 0;
    
    // Send the Finished Message
    tf_debug("[*] Sending Finished message");
    err = send_msg(TLSFinished(verify_data));
    return err;
}

mintls_error
TLSSession::process_finished(
    iarchive&               ar,                 // (I) Server Finished message
    TLSState&               state,              // (I/O) State governing the session
    send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
)
{
    tf_debug("[*] Received Finished");

    TLSFinished server_finished;
    ar & server_finished;

    state.handshake_data.resize(state.handshake_data.size() - server_finished.verify_data.size() - TLSHandshakeMsg::header_sz);

    std::vector<uint8_t> verify_data;
    calculate_finished_data(
        verify_data,                // (O) Verify Data
        state.master_secret,        // (I) Master Secret
        state.handshake_data,       // (I) Total handshake data
        state.cipher_suite,         // (I) Cipher
        "server finished"           // (I) Label
    );

    // Don't need it anymore
    state.handshake_data.clear();

    /// XXX constant time
    if (verify_data != server_finished.verify_data)
    {
        tf_dbg("[E] SERVER VERIFY: " << to_hex(verify_data));
        tf_dbg("[E] SERVER VERIFY: " << to_hex(server_finished.verify_data));
        return mintls_err_decrypt_error;
    }
    else
    {
        return mintls_success;
    }
}

mintls_error
TLSSession::process_changecipherspec(
    TLSState&               state               // (I/O) State governing the session
)
{
    tf_debug("[*] Received ChangeCipherSpec");
    state.server_encrypting = true;
    return mintls_success;
}

bool
TLSSession::server_kex_required() const
{
    KexMethod const kex_method = CipherSuites::kex_method(m_state.cipher_suite);
    switch (kex_method.underlying())
    {
    default:
        return false;
    case KexMethods::ECDHE_RSA:
    case KexMethods::DHE_RSA:
        return true;
    }
}

std::pair<mintls_error, bool>
expect_handshake_impl(
    std::function<mintls_error(iarchive&)> const& handler, // (I) Handler
    ContentType         content_type,   // (I) Content Type
    HandshakeType       handshake_type, // (I) Handshake Type
    bool const          bRequired,      // (I) Required
    uint8_t const *     payload,        // (I) Record (excluding header)
    size_t const        sz,             // (I) Size
    std::vector<uint8_t>& handshake_data// (O) Handshake data
)
{
    if (sz < 4) return std::make_pair(mintls_err_decode_error, true);

    if (content_type == ContentTypes::Handshake)
    {
        HandshakeType   type;
        size_t          length;
        TLSHandshakeMsg::read_header(&payload[0],type,length);

        if (length + 4 != sz)
        {
            tf_debug("[E] Type=%d HandshakeLength (%lu) != RecordLength (%lu)", type, length, sz - 4);
            return std::make_pair(mintls_err_decode_error, true);
        }

        if (type == handshake_type)
        {
            iarchive ar(payload+4, length);
            if (type != TLSHandshakeMsg::HelloRequest)
            {
                handshake_data.insert(handshake_data.end(), payload,payload+4+length);
            }
            mintls_error err = (handler)(ar);
            if (err == mintls_success && ar.left() > 0)
            {
                tf_debug("[E] Unexpected data after end of handshake message");
                err = mintls_err_decode_error;
            }
            return std::make_pair(err,true);
        }
        else
        {
            if (bRequired)
            {
                tf_debug("[*] Unexpected handshake message %d", type);
            }
            return std::make_pair(mintls_err_unexpected_message, bRequired);
        }
    }
    else
    {
        tf_debug("[E] Got unexpected record type (%lu)", content_type);
        return std::make_pair(mintls_err_unexpected_message,true);
    }
}

mintls_error
TLSSession::handle_record(
    TLSProtocolVersion const&   version,            // (I) Protocol Version
    ContentType                 content_type,       // (I) Content Type
    uint8_t const *             payload,            // (I) Record (excluding header)
    size_t                      sz                  // (I) Size
)
{
    if (content_type == ContentTypes::Alert)
    {
        uint8_t alert_level;
        uint8_t alert_description;

        iarchive ar(payload, sz);
        ar & alert_level & alert_description;

        mintls_error err = (mintls_error)alert_description;
        if (alert_level != 1)
        {
            tf_debug("[*] Received fatal alert %s", mintls_error_string(err));

            m_protocol_state = Disconnected;
            return err;
        }
        else
        {
            tf_debug("[*] Received warning alert %s", mintls_error_string(err));
            return mintls_success;
        }
    }

    // Quick and dirty coroutine macros, to perform the handshaking
    //
    // c.f. http://www.chiark.greenend.org.uk/~sgtatham/coroutine.h
    #define state_machine_start(x)      \
        int& state = (x);               \
        switch (state) { case 0:;       \

    #define state_machine_end(z)        \
        } state = 0; return z;


    #define expect_handshake(type_,fn,bRequired)   \
        do {                                    \
            state = __LINE__;                   \
            {                                   \
                using namespace std::placeholders; \
                std::function<mintls_error(TLSPlaintext const&)> send_msg_fn =           \
                std::bind(&TLSSession::send_msg, this, _1);             \
                                                    \
                std::pair<mintls_error, bool> err =     \
                expect_handshake_impl(              \
                    std::bind(&TLSSession::fn, _1, std::ref(m_state), std::cref(send_msg_fn)),   \
                    content_type,                   \
                    type_,                          \
                    bRequired,                      \
                    payload,                        \
                    sz,                             \
                    m_state.handshake_data          \
                );                                  \
                if (err.second) return err.first;   \
            }                                       \
            case __LINE__:;                         \
        } while (0);

    #define expect_changecipherspec(fn)         \
        do {                                    \
            state = __LINE__;                   \
            if (content_type == ContentTypes::ChangeCipherSpec)      \
            {                                   \
                if (sz != 1 || payload[0] != 0x1)\
                {                               \
                    tf_debug("[E] Invalid ChangeCipherSpec"); \
                    return mintls_err_unexpected_message; \
                }                               \
                return(fn(m_state));            \
            }                                   \
            else                                \
            {                                   \
                tf_debug("[E] Got unexpected record type (%lu)", content_type); \
                return mintls_err_unexpected_message; \
            }                                   \
            case __LINE__:;                     \
        } while (0);

    #define mandatory_handshake(type_,fn)    expect_handshake(type_,fn,true)
    #define optional_handshake(type_,fn)     expect_handshake(type_,fn,false)

    state_machine_start(m_handshake_yield_point)

    // Do the handshake
    mandatory_handshake (TLSHandshakeMsg::ServerHello,          process_server_hello)
    mandatory_handshake (TLSHandshakeMsg::Certificate,          process_certificate)
    if (server_kex_required())
    {
        mandatory_handshake(TLSHandshakeMsg::ServerKex,         process_server_kex);
    }
    optional_handshake  (TLSHandshakeMsg::CertificateReq,       handshake_unsupported)
    mandatory_handshake (TLSHandshakeMsg::ServerHelloDone,      process_server_hello_done)
    expect_changecipherspec(process_changecipherspec)
    mandatory_handshake (TLSHandshakeMsg::Finished,             process_finished);

    // XXX this isn't executed until the message proceeding the finished message, which isn't quite right
    m_protocol_state = Connected;

    // main loop
    if (content_type == ContentTypes::ApplicationData)
    {
        tf_debug("[*] Got application data");

        // Copy the data...
        m_read_buf.resize(m_read_buf.size() + sz);
        std::copy(payload,payload+sz,&m_read_buf[m_read_buf.size() - sz]);

        return mintls_success;
    }
    else
    {
        tf_debug("[*] Unexpected content type(%d)", content_type);
        return mintls_err_unexpected_message;
    }

    state_machine_end(mintls_err_internal_error);

}

// Received data from transport layer
// Should be TLS Record (RFC-5462 6.2)
mintls_error
TLSSession::handle_data(
    unsigned char const *   data,
    size_t const            data_sz
)
{
    // Copy the data
    m_recv_buf.insert(m_recv_buf.end(), data, data + data_sz);

    // Process records
    while (m_recv_buf.size() >  0)
    {
        // Check we have a full header
        if (m_recv_buf.size() < TLSRecord::header_sz)
            return mintls_pending;

        ContentType         content_type;
        TLSProtocolVersion  version;
        size_t              msg_sz;

        mintls_error err = TLSRecord::read_header(m_recv_buf, content_type, version, msg_sz);
        if (err != mintls_success)
        {
            return err;
        }

        // XXX doesn't quite work
        if (version != m_state.version)
        {
            return mintls_err_decode_error;
        }

        size_t const header_sz = TLSRecord::header_sz;
        tf_debug("[*] Received record [type=%d] [msg_sz=%d]", content_type, msg_sz);
        if (m_recv_buf.size() >= header_sz + msg_sz)
        {
            if (m_state.server_encrypting)
            {
                std::vector<uint8_t> payload;
                uint8_t const *encrypted_payload = &m_recv_buf[header_sz];

                // Decrypt the payload
                err =
                TLSRecord::decrypt_record_payload(
                    payload,                        // (O) Unencrypted record payload
                    m_state.server_seq_num++,       // (I) Sequence Number
                    content_type,                   // (I) Content type
                    version,                        // (I) Version
                    m_state.cipher_suite,           // (I) Cipher
                    m_state.server_key,             // (I) Key
                    m_state.server_mac_key,         // (I) MAC key
                    encrypted_payload,              // (I) Payload
                    msg_sz                          // (I) Payload size
                );

                // Remove the record from the receive buffer
                m_recv_buf.erase(m_recv_buf.begin(), m_recv_buf.begin() + header_sz + msg_sz);
                if (err == mintls_success)
                {
                    // Process this record
                    err = handle_record(version, content_type, &payload[0], payload.size());
                }
            }
            else
            {
                // Extract just the record payload, and put the remaining bytes into m_recv_buf
                std::vector<uint8_t> record;
                if (m_recv_buf.size() > header_sz+msg_sz)
                {
                    record.assign(m_recv_buf.begin()+header_sz+msg_sz,m_recv_buf.end());
                    m_recv_buf.resize(header_sz+msg_sz);
                }
                std::swap(record,m_recv_buf);

                // Process this record
                err = handle_record(version, content_type, &record[header_sz], msg_sz);
            }

            if (err != mintls_success)
            {
                // TODO send alert
                return err;
            }
        }
        else
        {
            // Still waiting for more data
            return mintls_pending;
        }
    }
    return mintls_success;
}

mintls_error
TLSSession::send_msg_impl(
    TLSPlaintext const &    msg,
    TLSState&               state,
    std::vector<uint8_t>&   send_buf
)
{
    mintls_error err;

    if (!state.client_encrypting)
    {
        size_t const old_sz = send_buf.size();

        err =
        TLSRecord::write_plaintext_record(
            send_buf,       // (O) Buffer to append to
            state.version,  // (I) Version
            msg             // (I) Payload
        );

        tf_debug("[*] Sending message sz=%d", send_buf.size() - old_sz - TLSRecord::header_sz);

        // Store the handshake data for later
        if (msg.content_type() == ContentTypes::Handshake)
        {
            state.handshake_data.insert(
                state.handshake_data.end(),
                send_buf.begin()+(old_sz+TLSRecord::header_sz),
                send_buf.end()
            );
        }
    }
    else
    {
        // Write out the plaintext
        std::vector<uint8_t> payload;
        msg.write_payload(payload);

        tf_debug("[*] Sending message sz=%d", payload.size());

        if (msg.content_type() == ContentTypes::Handshake)
        {
            // Store the handshake data for later
            state.handshake_data.insert(
                state.handshake_data.end(),
                payload.begin(),
                payload.end()
            );
        }

        ContentType type = msg.content_type();

        // Serialize the packet
        err =
        TLSRecord::write_encrypted_record(
            send_buf,                 // (O) Buffer to append to
            state.client_seq_num++,   // (I) Sequence number
            type,                     // (I) Content Type
            state.version,            // (I) Version
            state.cipher_suite,       // (I) Cipher
            state.client_key,         // (I) Key
            state.client_mac_key,     // (I) MAC key
            payload                   // (I) Payload
        );
    }

    return err;
}

mintls_error
TLSSession::send_msg(TLSPlaintext const & msg)
{
    return send_msg_impl(msg, m_state, m_send_buf);
}

// Received data from transport layer
mintls_error
TLSSession::received_data(
    unsigned char const *   data,
    size_t const            data_sz
) throw()
{
    if (m_protocol_state == Disconnected)
    {
        return mintls_disconnected;
    }

    mintls_error err = mintls_success;
    try {
         err = handle_data(data, data_sz);
    }
    catch (TLSException const& e)
    {
        tf_debug("[E] TLS Error (%d): %s", e.err(),e.msg());
        err = e.err();
    }
    catch (archive::error const& e)
    {
        tf_debug("[E] Error decoding record (%s)", typeid(e).name());
        // This case usually means there is some out of bounds error
        err = mintls_err_decode_error;
    }
    catch (asn1::ber_decoding_error const& e)
    {
        tf_debug("[E] Error decoding record (%s)", e.what());
        err = mintls_err_decode_error;
    }
    catch (std::exception const& e)
    {
        tf_debug("[E] Exception processing record (%s)", e.what());
        //  An internal error unrelated to the peer or the correctness of the protocol
        err = mintls_err_internal_error;
    }

    if (err != mintls_success && err != mintls_pending)
    {
        // TODO: send alert message
        m_protocol_state = Disconnected; 
    }

    return err;
}

mintls_error
TLSSession::pending_data(
    unsigned char const **  data,
    size_t  *               data_sz
) throw()
{
    if (m_send_buf.size() == 0)
    {
        m_send_buf_tmp.clear();

        *data       = NULL;
        *data_sz    = 0;

        return mintls_success;
    }
    else
    {
        // Move to temporary buffer
        std::swap(m_send_buf, m_send_buf_tmp);
        m_send_buf.clear();

        // Return data to user
        *data       = &m_send_buf_tmp[0];
        *data_sz    = m_send_buf_tmp.size();

        return mintls_success;
    }
}


mintls_error
TLSSession::write_data(
    unsigned char const *   data,
    size_t const            data_sz
) throw()
{
    class ApplicationData : public TLSPlaintext
    {
    public:
        ApplicationData(
            unsigned char const *   data,
            size_t const            data_sz
        ) :
        m_data(data),
        m_data_sz(data_sz)
        {}

        virtual void 
        write_payload(std::vector<uint8_t>& payload) const
        {
            payload.resize(payload.size() + m_data_sz);
            std::copy(m_data, m_data + m_data_sz, &payload[payload.size() - m_data_sz]);
        }

        virtual ContentType
        content_type() const
        {
            return ContentTypes::ApplicationData;
        }
    private:
        unsigned char const *   m_data;
        size_t const            m_data_sz;
    };

    /// XXX catch exceptions
    return send_msg(ApplicationData(data,data_sz));
}

mintls_error
TLSSession::read_data(
    unsigned char const **  data,
    size_t *                data_sz
) throw()
{
    if (m_read_buf.size() == 0)
    {
        m_read_buf_tmp.clear();

        *data       = NULL;
        *data_sz    = 0;

        return mintls_success;
    }
    else
    {
        // Move to temporary buffer
        std::swap(m_read_buf, m_read_buf_tmp);
        m_read_buf.clear();

        // Return data to user
        *data       = &m_read_buf_tmp[0];
        *data_sz    = m_read_buf_tmp.size();

        return mintls_success;
    }
}