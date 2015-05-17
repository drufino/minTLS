/* TLS Client Session
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_client_hpp
#define tf_tls_client_hpp
#include <tls/tls_ciphersuites.hpp>
#include <tls/tls_protocol.hpp>
#include <tls/tls_handshake.hpp>
#include <tls/tls_certificate.hpp>
#include <tls/tls_state.hpp>
#include <tls/tls_config.hpp>
#include "random.h"
#include "hash.h"
#include "cipher.h"
#include <core/tf_debug.hpp>
#include <functional>

class BigInt;


//////////////////////////////////////////////////////////////
//
// The internal C++ implementation of the TLS stack
//
// Primary reference
//  - [1] http://tools.ietf.org/html/rfc5246
//
class TLSSession
{
public:
    enum Side {
        Client=0,
        Server=1
    };

    enum State {
        Handshaking=0,
        Connected=1,
        Disconnected=2 
    };

    static unsigned const MAX_PLAINTEXT_SIZE = 16*1024;

    // Constructor
    TLSSession(Side side);

    // Parse record into various protocol
    mintls_error
    handle_record(
        TLSProtocolVersion const&   version,            // (I) Protocol Version
        ContentType                 content_type,       // (I) Content Type
        uint8_t const *             record,             // (I) Record (excluding header)
        size_t                      sz                  // (I) Size
    );

    // Split up data into records ([1] 6.2)
    mintls_error
    handle_data(
        unsigned char const *   data,
        size_t const            data_sz
    );

    // Received data from transport layer
    mintls_error
    received_data(
        unsigned char const *   data,
        size_t const            data_sz
    ) throw();

    // Data ready to go out via transport layer
    mintls_error
    pending_data(
        unsigned char const **  data,
        size_t  *               data_sz
    ) throw();

    // Write data from the application layer
    mintls_error
    write_data(
        unsigned char const *   data,
        size_t const            data_sz
    ) throw();

    mintls_error
    read_data(
        unsigned char const **  data,
        size_t *                data_sz
    ) throw();

    TLSConfig const& get_config() const { return m_config; }
    mintls_error     set_config(TLSConfig const& config);

private:

    /* Here we define the methods which handle each part of the handshake protocol. Note that handshake
     * messages must be received in strict order, otherwise the handshake should fail. This
     * is not checked by these routines, and these should be enforced at a higher level.
     *
     * The methods are static in order to facilitate simpler unit testing of the handshake protocol.
     */

    typedef std::function<mintls_error(TLSPlaintext const&)> send_msg_fn;

    static mintls_error
    process_server_hello_impl(
        TLSServerHello const&   server_hello,       // (I) ServerHello message
        TLSState&               state,              // (I/O) State governing the Session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing messages
    );

    static mintls_error
    process_server_hello(
        iarchive&               ar,                 // (I) ServerHello message
        TLSState&               state,              // (I/O) State governing the Session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing handshake messages
    );

    static mintls_error
    process_certificate(
        iarchive&               ar,                 // (I) Certificates message
        TLSState&               state,              // (I/O) State governing the Session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing handshake messages
    );

    static mintls_error
    process_server_kex(
        iarchive&               ar,                 // (I) ServerKeyExchanage message
        TLSState&               state,              // (I/O) State governing the session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing handshake messages
    );

    static mintls_error
    process_server_hello_done(
        iarchive&               ar,                 // (I) ServerHelloDone message
        TLSState&               state,              // (I/O) State governing the session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing handshake messages
    );

    static mintls_error
    handshake_unsupported(
        iarchive&               ar,                 // (I) Handshake message
        TLSState&               state,              // (I/O) State governing the session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing handshake messages
    );

    static mintls_error
    process_finished(
        iarchive&               ar,                 // (I) Server Finished message
        TLSState&               state,              // (I/O) State governing the session
        send_msg_fn const&      send_msg            // (I) Functor to allow outgoing handshake messages
    );

    static mintls_error 
    process_changecipherspec(
        TLSState&               state               // (I/O) State governing the session
    );

    bool     server_kex_required() const;

    mintls_error
    send_msg(
        TLSPlaintext const &    msg                 // (I) Record
    );

    static mintls_error
    send_msg_impl(
        TLSPlaintext const&     msg,                // (I) Record
        TLSState&               state,              // (I/O) State
        std::vector<uint8_t>&   send_buf            // (O) Send buffer
    );

    TLSConfig               m_config;                   // Configuration

    Side                    m_side;                     // Client or Server
    State                   m_protocol_state;           // State
    int                     m_handshake_yield_point;    // Current position in the handshake 
    TLSState                m_state;                    // Session State

    std::vector<uint8_t>    m_recv_buf;                 // Buffer for incoming data
    std::vector<uint8_t>    m_send_buf;                 // Buffer for outgoing transport data
    std::vector<uint8_t>    m_send_buf_tmp;             // Temporary buffer used by the C API

    std::vector<uint8_t>    m_read_buf;                 // Buffer for incoming application data
    std::vector<uint8_t>    m_read_buf_tmp;             // Temporary buffer used by the C API
};

#endif
