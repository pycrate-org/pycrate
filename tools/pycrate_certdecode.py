#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.7
# *
# * Copyright 2024. Benoit Michau.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_certdecode.py
# * Created : 2024-02-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import os
import sys
import argparse
import base64
import re
from binascii import unhexlify

from pycrate_asn1rt.asnobj import ASN1Obj


SOC = '-----BEGIN CERTIFICATE-----'
EOC = '-----END CERTIFICATE-----'


def main():
    
    parser = argparse.ArgumentParser(description='''
    Tries to decode the provided x.509 certificate and print the resulting structure.
    Assumes PEM format by default.
    Uses the RFC 5912 ASN.1 format by default.
    ''')
    
    parser.add_argument('-i', dest='input', type=str,
                        help='file containing the binary encoded objects')
    parser.add_argument('-s', dest='stream', type=str,
                        help='hexadecimal string encoding the objects')
    parser.add_argument('-o', dest='offset', type=int, default=0,
                        help='offset to start decoding at')
    parser.add_argument('-r', dest='raw', action='store_true',
                        help='consider the input as a raw binary encoded certificate instead of PEM')
    parser.add_argument('-t', dest='itut', action='store_true',
                        help='use the Certificate ASN.1 definition from ITU-T 2016 instead of the RFC 5912')
    parser.add_argument('-j', dest='jer', action='store_true',
                        help='print a JSON-encoded output instead of an ASN.1-encoded one')
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='print additional debugging info from the decoding')
    #
    args = parser.parse_args()
    #
    # get the input
    if args.input:
        try:
            if args.raw:
                fd = open(args.input, 'rb')
            else:
                fd = open(args.input, 'r')
        except:
            print('%s, args error: file %s not found' % (sys.argv[0], args.input))
            return 1
        buf = fd.read()[args.offset:]
        fd.close()
    elif args.stream:
        try:
            buf = unhexlify(args.stream)[args.offset:]
        except:
            print('%s, args error: invalid hex stream %s' % (sys.argv[0], args.stream))
            return 1
    else:
        print('%s, args error: missing input encoded object' % sys.argv[0])
        return 1
    #
    # extract the DER-encoded cert
    if args.raw:
        # raw DER-encoded buffer
        cert = buf
    else:
        # assume PEM
        off = buf.find(SOC)
        if off < 0:
            print('%s, input error: start of PEM certificate string not found' % sys.argv[0])
            return 1
        buf = buf[off + len(SOC):]
        off = buf.find(EOC)
        if off < 0:
            print('%s, input error: end of PEM certificate string not found' % sys.argv[0])
            return 1
        buf = buf[:off]
        if not buf.isascii():
            print('%s, input error: non-ascii input detected, invalid for PEM' % sys.argv[0])
            return 1
        buf = re.sub(r'\s{1,}', '', buf)
        try:
            cert = base64.decodebytes(buf.encode('ascii'))
        except Exception as err:
            print('%s, input error: invalid base64 PEM content, %r' % (sys.argv[0], err))
            return 1
    #
    # set silent mode
    ASN1Obj._SILENT = True
    #
    # decode the cert
    if args.itut:
        from pycrate_asn1dir import X509_2016
        CertObj = X509_2016.AuthenticationFramework.Certificate
    else:
        from pycrate_asn1dir import RFC5912
        CertObj = RFC5912.PKIX1Explicit_2009.Certificate
    if args.verbose:
        ASN1Obj._SILENT = False
    try:
        CertObj.from_der(cert)
    except Exception as err:
        print('%s, content error: unable to decode the certificate, %r' % (sys.argv[0], err))
        return 1
    if args.jer:
        print(CertObj.to_jer())
    else:
        print(CertObj.to_asn1())
    #
    return 0


if __name__ == '__main__':
    sys.exit(main())
