#!/usr/bin/env python
#
# Quick and dirty script to genrate master secret test cases from openssl and GnuTLS debugging output
# Currently does TLS1.2 only
#
# Tested with OpenSSL 1.0.2 and GnuTLS 3.2.17
#

import subprocess,time,re,string

openssl='/usr/local/Cellar/openssl/1.0.2/bin/openssl'
gnutls='/usr/local/bin/gnutls-cli'

test_cases = [
    ('PRF_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA','DHE-RSA-AES128-SHA'),
    ('PRF_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA256','DHE-RSA-AES128-SHA256'),
    ('PRF_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA','DHE-RSA-AES256-SHA'),
    ('PRF_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA256','DHE-RSA-AES256-SHA256'),
    ('PRF_SHA384','TLS_RSA_WITH_AES_256_GCM_SHA384','DHE-RSA-AES256-GCM-SHA384')
]

def do_test(test_case):
    prf = test_case[0]
    tinfoil_cipher = test_case[1]
    openssl_cipher = test_case[2]
    openssl_args = [openssl,'s_server','-key','server.key','-cert','server.crt','-dhparam','dhparam.pem','-cipher',openssl_cipher] 
    #print '[*] %s' % ' '.join(openssl_args)
    openssl_server = subprocess.Popen(openssl_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    #print openssl_server
    gnutls_args = [gnutls,'--insecure','-d','9','127.0.0.1','-p','4433']
    #print '[*] %s' % ' '.join(gnutls_args)
    gnutls_client = subprocess.Popen(gnutls_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    time.sleep(1)
    gnutls_output = gnutls_client.communicate()[0]
    openssl_server.terminate()
    gnutls_client.wait()
    '''
    |<9>| INT: PREMASTER SECRET[32]: 9916aab50313886102878dd0d3cbf8d6ce5279b0796e2ad1781844b3ac1d3a07
    |<9>| INT: CLIENT RANDOM[32]: 544d60a7e2d1ca9bef095df6931258d2e5df95a678369a7abd107f00dd6f2750
    |<9>| INT: SERVER RANDOM[32]: a32ffbd0a0f9ec43fc3761cd8afce5c4e4db92c97137d0546cdc2240d3fb7487
    |<9>| INT: MASTER SECRET: c6252ef49ee819c3b0f65db9d2277b84a082696a5aba710f36db2afe6647d610b873308df2ca50540d6efd7854c75d42
    |<4>| REC[0x7fef2c00ba00]: Initializing epoch #1
    |<9>| INT: KEY BLOCK[40]: 538e57f82cf37b070af6cc637a83d60021d3301c3e2d2e2b4d0ba53b2d899929
    |<9>| INT: CLIENT WRITE KEY [16]: 538e57f82cf37b070af6cc637a83d600
    |<9>| INT: SERVER WRITE KEY [16]: 21d3301c3e2d2e2b4d0ba53b2d899929
    '''
    data = {}
    for line in gnutls_output.split('\n'):
        result = re.match('.*INT: (.*)\[.*\]: ([a-f0-9]*)',line)
        if result is None:
            result = re.match('.*INT: (.*): ([a-f0-9]*)',line)

        if not (result is None):
            name = string.rstrip(result.groups()[0])
            value = result.groups()[1]
            data[name] = value
    client_mac_key = data['CLIENT MAC KEY'] if data.has_key('CLIENT MAC KEY') else ''
    server_mac_key = data['SERVER MAC KEY'] if data.has_key('SERVER MAC KEY') else ''
    print \
"""
   {PRFModes::%s, CipherSuites::%s,
    // PREMASTER SECRET
    "%s",
    // CLIENT RANDOM
    "%s",
    // SERVER RANDOM
    "%s",
    // MASTER SECRET
    "%s",
    // CLIENT KEY
    "%s",
    // SERVER KEY
    "%s",
    // CLIENT MAC KEY
    "%s",
    // SERVER MAC KEY
    "%s"
   },
""" %  (prf,tinfoil_cipher,data['PREMASTER SECRET'],data['CLIENT RANDOM'],data['SERVER RANDOM'],data['MASTER SECRET'],data['CLIENT WRITE KEY'],data['SERVER WRITE KEY'],client_mac_key,server_mac_key)

for i in range(len(test_cases)):
    do_test(test_cases[i])
