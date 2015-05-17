/* TLS Session State
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_state_hpp
#define tf_tls_state_hpp
#include <tls/tls_protocol.hpp>
#include <tls/tls_certificate.hpp>
 
class TLSState
{
public:
    // Default constructor
    TLSState();

    TLSProtocolVersion      version;                    // TLS Version

    std::vector<uint8_t>    client_random;              // Client random material (including epoch)
    std::vector<uint8_t>    server_random;              // Server random material (including epoch)
    uint8_t                 comp_method;                // Compression method
    CipherSuite             cipher_suite;               // Cipher Suite
    std::vector<uint8_t>    public_key;                 // Client Public Key

    std::vector<uint8_t>    handshake_data;             // Handshake data

    bool                    client_encrypting;          // Encrypting
    bool                    server_encrypting;          // Encrypting
    uint64_t                client_seq_num;             // Client sequence number
    uint64_t                server_seq_num;             // Server sequence number
    std::vector<uint8_t>    master_secret;              // Master Secret
    std::vector<uint8_t>    client_mac_key;             // Client MAC key
    std::vector<uint8_t>    server_mac_key;             // Server MAC key
    std::vector<uint8_t>    client_key;                 // Client key
    std::vector<uint8_t>    server_key;                 // Server key

    vararray<x509::Certificate>::_24 certificates;      // Certificates
};

#endif