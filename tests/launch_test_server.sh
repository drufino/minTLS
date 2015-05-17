#!/bin/sh
/usr/local/Cellar/openssl/1.0.2/bin/openssl s_server  -key server.key -cert server.crt -msg -debug -dhparam dhparam.pem -named_curve prime256v1

