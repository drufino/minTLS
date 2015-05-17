#!/usr/bin/env python
"""
  Small utility to compare output from 'cert_parse' with OpenSSL. The certificates are available from

  https://scans.io
"""
from subprocess import PIPE, Popen
import sys,string

def fold_text(my_string):
    return string.join([my_string[x:x+64] for x in range(0,len(my_string),64)],'\n')

for line in sys.stdin:
    base64 = string.rstrip(line[41:])
    folded = fold_text(base64)
    tmp_cert = \
"""\
-----BEGIN CERTIFICATE-----
%s
-----END CERTIFICATE-----\
""" % folded
    f = open('/tmp/tmp.crt','wb')
    f.write(tmp_cert)
    f.close()
    p = Popen(['/usr/local/Cellar/openssl/1.0.2/bin/openssl', 'x509','-text','-noout','-in','/tmp/tmp.crt'],stdin=PIPE,stdout=PIPE)
    openssl_output = p.stdout.read()[:-1]
    p.communicate()[0]
    q = Popen(['./cert_parse','/tmp/tmp.crt'],stdin=PIPE,stdout=PIPE)
    tf_output = q.stdout.read()[:-1]
    q.communicate()[0]
    if openssl_output == tf_output:
        print 'Equal!'
    else:
        print 'base64=\n-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' % fold_text(base64)
        f = open('/tmp/tmp0','wb')
        f.write(openssl_output)
        f.close()
        f = open('/tmp/tmp1','wb')
        f.write(tf_output)
        f.close()
        p = Popen(['/usr/bin/diff', '-C', '2', '/tmp/tmp0', '/tmp/tmp1'], stdin=PIPE, stdout=PIPE)
        print p.stdout.read()
        p.communicate()[0]
