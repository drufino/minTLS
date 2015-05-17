/*
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#include "tls_api.h"
#include "tls_client.hpp"
#include "core/tf_debug.hpp"
#include <vector>
#include <cstdlib>

#define RETURN_IF_FAIL(x) { mintls_error err = (x); if (err != mintls_success) return err; }

typedef std::vector<uint8_t> byte_array;

extern "C" {

const char *
mintls_error_string(enum mintls_error err)
{
    switch (err)
    {
    case mintls_success:
        return "SUCCESS";
    case mintls_failed:
        return "FAILED";
    case mintls_pending:
        return "PENDING";
    case mintls_abort:
        return "ABORTED";
    case mintls_disconnected:
        return "DISCONNECTED";

    // TLS Error Alerts (RFC-5246 7.2)
    case mintls_err_unexpected_message:
        return "UNEXPECTED_MESSAGE";
    case mintls_err_bad_record_mac:
        return "BAD_RECORD_MAC";
    case mintls_err_decryption_failed:
        return "DECRYPTION_FAILED";
    case mintls_err_record_overflow:
        return "RECORD_OVERFLOW";
    case mintls_err_decompression_failed:
        return "DECOMPRESSION_FAILED";
    case mintls_err_handshake_failed:
        return "HANDSHAKE_FAILED";
    case mintls_err_no_certificate:
        return "NO_CERTIFICATE";
    case mintls_err_bad_certificate:
        return "BAD_CERTIFICATE";
    case mintls_err_unsupported_certificate:
        return "UNSUPPORTED_CERTIFICATE";
    case mintls_err_certificate_revoked:
        return "CERTIFICATE_REVOKED";
    case mintls_err_certificate_expired:
        return "CERTIFICATE_EXPIRED";
    case mintls_err_certificate_unknown:
        return "CERTIFICATE_UNKNOWN";
    case mintls_err_illegal_parameter:
        return "ILLEGAL_PARAMETER";
    case mintls_err_unknown_ca:
        return "UNKNOWN_CA";
    case mintls_err_access_denied:
        return "ACCESS_DENIED";
    case mintls_err_decode_error:
        return "DECODE_ERROR";
    case mintls_err_decrypt_error:
        return "DECRYPT_ERROR";
    case mintls_err_protocol_version:
        return "PROTOCOL_VERSION";
    case mintls_err_insufficient_security:
        return "INSUFFICIENT_SECURITY";
    case mintls_err_internal_error:
        return "INTERNAL_ERROR";
    case mintls_err_user_cancelled:
        return "USER_CANCELLED";
    case mintls_err_no_renegotiation:
        return "NO_RENEGOTIATION";
    case mintls_err_unsupported_extension:
        return "UNSUPPORTED_EXTENSION";
    default:
        return "UNKNOWN_ERROR";
    }
}
}



/*
 * The external C interface to the TLS stack
 */
extern "C" {

struct mintls_session_t {};

#define WRAP(x) reinterpret_cast<mintls_session *>(x)
#define UNWRAP(x) reinterpret_cast<TLSSession *>(x)

mintls_session *
mintls_create_client_session()
{
    return WRAP(new TLSSession(TLSSession::Client));
}

enum mintls_error
mintls_configure(
    mintls_session *        session,        // (I) Session
    enum mintls_config      var,            // (I) Variable ENUM
    const char *            value           // (I) Value
)
{
    TLSConfig config = UNWRAP(session)->get_config();

    switch (var)
    {
    case mintls_config_root_certificate:
        config.ca_root_file = value;
        return mintls_success;
    case mintls_config_trust:
        if (!strcasecmp(value, "FULL"))
        {
            config.trust_type = TrustTypes::FULL;
            return mintls_success;
        }
        else if (!strcasecmp(value, "CHAIN"))
        {
            config.trust_type = TrustTypes::CHAIN;
            return mintls_success;
        }
        else if (!strcasecmp(value, "NONE"))
        {
            config.trust_type = TrustTypes::NONE;
            return mintls_success;
        }
        else
        {
            return mintls_failed;
        }
        break;
    default:
        return mintls_failed;
    }
}

void
mintls_destroy_session(mintls_session *session)
{
    delete UNWRAP(session);
}

mintls_error
mintls_received_data(
    mintls_session *        session,
    unsigned char const *   data,
    size_t const            data_sz
)
{
    return UNWRAP(session)->received_data(data,data_sz);
}

mintls_error
mintls_pending_data(
    mintls_session *        session,
    unsigned char const **  data,
    size_t *                data_sz
)
{
    return UNWRAP(session)->pending_data(data, data_sz);
}

mintls_error
mintls_write_appdata(
    mintls_session *        session,    // (I) Session
    unsigned char const*    data,       // (I) Outgoing data for application layer
    size_t                  data_sz     // (I) Number of bytes
)
{
    return UNWRAP(session)->write_data(data, data_sz);
}

mintls_error
mintls_read_appdata(
    mintls_session *        session,    // (I) Session
    unsigned char const**   data,       // (O) Incoming data for the application layer
    size_t*                 data_sz     // (O) Number of bytes
)
{
    return UNWRAP(session)->read_data(data,data_sz);
}

void
mintls_enable_debugging()
{
    tf_debug_enable();
}

}
