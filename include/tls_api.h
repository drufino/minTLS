/* Public interface to TLS session, with support for
 * 
 *    - TLS v1.2
 *    - AEAD ciphers
 *    - PFS Key Exchange
 *
 * References are 
 *    [1] http://www.ietf.org/rfc/rfc5246.txt (TLS v1.2)
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_api_h
#define mintls_api_h
#include <stdlib.h>
 
#ifdef __cplusplus
extern "C" {
#endif 

enum mintls_error
{
    mintls_success = 0,     // Success
    mintls_failed  = 1,     // Failed
    mintls_pending = 2,     // Need more data
    mintls_abort   = 3,     // Abort
    mintls_disconnected=4,  // Disconnected

    // TLS Error Alerts (RFC-5246 7.2)
    mintls_err_unexpected_message   =10,
    mintls_err_bad_record_mac       =20,
    mintls_err_decryption_failed    =21,
    mintls_err_record_overflow      =22,
    mintls_err_decompression_failed =30,
    mintls_err_handshake_failed     =40,
    mintls_err_no_certificate       =41,
    mintls_err_bad_certificate      =42,
    mintls_err_unsupported_certificate=43,
    mintls_err_certificate_revoked  =44,
    mintls_err_certificate_expired  =45,
    mintls_err_certificate_unknown  =46,
    mintls_err_illegal_parameter    =47,
    mintls_err_unknown_ca           =48,
    mintls_err_access_denied        =49,
    mintls_err_decode_error         =50,
    mintls_err_decrypt_error        =51,
    mintls_err_protocol_version     =70,
    mintls_err_insufficient_security=71,
    mintls_err_internal_error       =80,
    mintls_err_user_cancelled       =90,
    mintls_err_no_renegotiation     =100,
    mintls_err_unsupported_extension=110
};

enum mintls_config
{
    // File to load the list of root certificates
    mintls_config_root_certificate  =0,
    // Allow to configure chain of trust verification FULL,CHAIN,NONE. Defaults to FULL.
    mintls_config_trust             =1
};

const char *
mintls_error_string(enum mintls_error err);

// Deliberately opaque
struct mintls_session_t;
typedef struct mintls_session_t mintls_session;

/*
 * Create client session.
 */
mintls_session *
mintls_create_client_session();

/*
 * Configure the session beyond the defaults.
 */
enum mintls_error
mintls_configure(
    mintls_session *        session,        // (I) Session
    enum mintls_config      var,            // (I) Variable ENUM
    const char *            value           // (I) Value
);

/*
 * Destroy the session
 */
void
mintls_destroy_session(mintls_session *session);

/*
 * Process data from transport layer
 */
enum mintls_error
mintls_received_data(
    mintls_session *        session,    // (I) Session
    unsigned char const *   data,       // (I) Data received from transport layer
    size_t const            data_sz     // (I) Number of bytes 
);

/*
 * Data pending for transport layer
 */
enum mintls_error
mintls_pending_data(
    mintls_session *        session,    // (I) Session
    unsigned char const **  data,       // (O) Pointer to data pending for transport layer
    size_t *                data_sz     // (O) Number of bytes
);

/*
 * Read data at application layer 
 */
enum mintls_error
mintls_read_appdata(
    mintls_session *        session,    // (I) Session
    unsigned char const**   data,       // (O) Incoming data for the application layer
    size_t*                 data_sz     // (O) Number of bytes
);

/*
 * Write data at application lyer
 */
enum mintls_error
mintls_write_appdata(
    mintls_session *        session,    // (I) Session
    unsigned char const*    data,       // (I) Outgoing data for application layer
    size_t                  data_sz     // (I) Number of bytes
);

/*
 * Turn on debugging to stderr
 */
void
mintls_enable_debugging();

#ifdef __cplusplus
}
#endif

#endif
