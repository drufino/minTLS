#!/usr/bin/env python
"""
   Utility to decompress the certificates obtained from https://scans.io
"""
import sys,string

for line in sys.stdin:
    base64 = string.rstrip(line[41:])
    folded = string.join([base64[x:x+64] for x in range(0, len(base64), 64)],'\n')
    print \
"""\
-----BEGIN CERTIFICATE-----
%s
-----END CERTIFICATE-----\
""" % folded

