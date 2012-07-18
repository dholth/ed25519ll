#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import os.path
import pkg_resources
from distutils.util import get_platform
try:
    import sysconfig
except ImportError:
    from distutils import sysconfig    

plat_name = get_platform().replace('-', '_')
so_suffix = sysconfig.get_config_var('SO')
lib_filename = pkg_resources.resource_filename('ed25519ll', '_ed25519_%s%s' %
                                               (plat_name, so_suffix))

from cffi import FFI
ffi = FFI()

decl = """
    extern int crypto_sign(unsigned char *, unsigned long long *,
        const unsigned char *, unsigned long long, const unsigned char *);
    
    extern int crypto_sign_open(unsigned char *, unsigned long long *, 
        const unsigned char *, unsigned long long, const unsigned char *);
    
    extern int crypto_sign_keypair(unsigned char *pk, unsigned char *sk, 
        unsigned char *seed);
"""
        
ffi.cdef(decl)

verify = False

if not verify:
    ed25519 = ffi.dlopen(os.path.abspath(lib_filename))
else:
    # set LIBRARY_PATH to pwd or use -L
    ed25519 = ffi.verify(decl, libraries=["ed25519"]) # library_dirs = []

PUBLICKEYBYTES=32
SECRETKEYBYTES=64
SIGNATUREBYTES=64

seed = os.urandom(PUBLICKEYBYTES)

pk = ffi.new('unsigned char[32]')
sk = ffi.new('unsigned char[64]')
s = ffi.new('unsigned char[32]', map(ord, seed))

# generate public and signing key from seed (should save pk, sk; not
# guaranteed to derive keys the same way in the future)
rc = ed25519.crypto_sign_keypair(pk, sk, s)

message = b'Mares eat oats'
msg = ffi.new('unsigned char[]', map(ord, message))

sig_and_msg = ffi.new('unsigned char[]', (len(message) + SIGNATUREBYTES))
# if I don't want a pointer, ffi.cast("unsigned long long", 42)
sig_and_msg_len = ffi.new('unsigned long long')

# sign a message
rc2 = ed25519.crypto_sign(sig_and_msg, sig_and_msg_len, msg, len(message), sk)

# note rc should always be 0 on success
# sig is the first SIGNATUREBYTES bytes of sig_and_msg
# a copy of msg is in the remainder

newmsg = ffi.new('unsigned char[%d]' % (len(message) + SIGNATUREBYTES))
msg_len = ffi.new('unsigned long long', len(msg))
rc3 = ed25519.crypto_sign_open(newmsg, msg_len, sig_and_msg, sig_and_msg_len[0], pk)

# for example the message is
# ''.join(chr(x) for x in newmsg)[:msg_len[0]]
#
# str(ffi.buffer(newmsg, msg_len[0]))
