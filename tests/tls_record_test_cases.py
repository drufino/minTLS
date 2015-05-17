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
    ('PRF_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA','DHE-RSA-AES128-SHA',20),
    ('PRF_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA256','DHE-RSA-AES128-SHA256',32),
    ('PRF_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA','DHE-RSA-AES256-SHA',20),
    ('PRF_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA256','DHE-RSA-AES256-SHA256',32),
#    ('PRF_SHA384','TLS_RSA_WITH_AES_256_GCM_SHA384','DHE-RSA-AES256-GCM-SHA384',48)
]

plaintext_examples = \
    [
        'a\n',
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
    ]

def do_test(test_case):
    prf = test_case[0]
    tinfoil_cipher = test_case[1]
    openssl_cipher = test_case[2]
    openssl_args = [openssl,'s_server','-msg','-debug','-key','server.key','-cert','server.crt','-dhparam','dhparam.pem','-cipher',openssl_cipher] 
    #print '[*] %s' % ' '.join(openssl_args)
    openssl_server = subprocess.Popen(openssl_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    gnutls_args = [gnutls,'--insecure','-d','9','127.0.0.1','-p','4433']
    #print '[*] %s' % ' '.join(gnutls_args)
    gnutls_client = subprocess.Popen(gnutls_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    #print '[*] Writing'
    these_examples = [plaintext_examples[0]]


    # Create example of boundary case around block length 
    mac_length = test_case[3]
    block_length = 16
    padded_length = ((mac_length+block_length+2)/block_length + 1)*block_length
    pt_length = padded_length - block_length - mac_length
    these_examples.append('a'*(pt_length-2) + '\n')
    these_examples.append('a'*(pt_length-1) + '\n')
    these_examples.append('a'*(pt_length-2+block_length) + '\n')
    these_examples.append('a'*(pt_length-1+block_length) + '\n')
    these_examples += plaintext_examples[1:]
    for pt in these_examples:
        gnutls_client.stdin.write(pt)
        gnutls_client.stdin.flush()
        time.sleep(0.2)
    gnutls_client.terminate()
    openssl_stdout,openssl_stderr = openssl_server.communicate()
    openssl_server.wait()
    gnutls_output = gnutls_client.communicate()[0]
    '''
read from 0x7f9723d002a0 [0x7f9724808003] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 30                                    ....0
<<< ??? [length 0005]
    17 03 03 00 30
a
read from 0x7f9723d002a0 [0x7f9724808008] (48 bytes => 48 (0x30))
0000 - 37 cb ca 73 70 d2 45 fb-af 49 8e c7 47 b1 81 60   7..sp.E..I..G..`
0010 - 49 6c 3a 80 23 6c a6 75-f4 58 c7 45 c2 2b de 4f   Il:.#l.u.X.E.+.O
0020 - 45 2a 2c c4 4c 75 4b b9-1b 66 d1 1e 5e 99 76 a3   E*,.LuK..f..^.v.
    '''
    lines = openssl_stdout.split('\n')
    lines.reverse()
    while len(lines) > 0:
        line = lines.pop()
        if line[:9] == 'CIPHER is':
            break
    encrypted_records = []
    while len(lines) > 0:
        while len(lines) > 0: 
            line = lines.pop() 
            if line[:9] == 'read from':
                break;
        data = ''
        while len(lines) > 0:
            line = lines[-1]
            if line[4:7] != ' - ':
                break
            lines.pop()
            result = re.match('[0-9]{4} - (.{47}).*',line)
            tmp = result.groups()[0]
            tmp = tmp.replace(' ','').replace('-','')
            data = data + tmp
        while len(lines) > 0:
            line = lines.pop()
            if line[:9] == 'read from':
                break;
        while len(lines) > 0:
            line = lines[-1]
            if line[4:7] != ' - ':
                break
            lines.pop()
            result = re.match('[0-9]{4} - (.{47}).*',line)
            tmp = result.groups()[0]
            tmp = tmp.replace(' ','').replace('-','')
            data = data + tmp
        if len(data) > 0:
            encrypted_records.append(data)

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
    assert(len(encrypted_records) == len(these_examples))
    print '''\
        {
            CipherSuites::%s,
            ApplicationData,
            "%s",
            "%s",
            %d,''' % (tinfoil_cipher,data['CLIENT WRITE KEY'],data['CLIENT MAC KEY'],len(encrypted_records))
    print '''\
            {'''
    for i,(ct,pt) in enumerate(zip(encrypted_records,these_examples)):
        print '''\
                {
                    "%s",
                    %d,
                    "%s"
                },''' % (string.replace(pt,'\n','\\n'),i+1,ct)
    print '''\
            }
        },'''


for i in range(len(test_cases)):
    do_test(test_cases[i])
