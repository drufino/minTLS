#include "tls_state.hpp"

TLSState::TLSState()
:
    version(),
    comp_method(0),
    cipher_suite(CipherSuites::type(0)),
    client_encrypting(false),
    server_encrypting(false),
    client_seq_num(0),
    server_seq_num(0)
{

}