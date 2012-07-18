#!/usr/bin/env python
# -*- coding: utf-8 -*-

import warnings
import os
import os.path
import pkg_resources
from distutils.util import get_platform
from collections import namedtuple
try:
    import sysconfig
except ImportError:
    from distutils import sysconfig
    
__all__ = ['crypto_sign', 'crypto_sign_open', 'crypto_sign_keypair']

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
    plat_name = get_platform().replace('-', '_')
    so_suffix = sysconfig.get_config_var('SO')
    lib_filename = pkg_resources.resource_filename('ed25519ll', '_ed25519_%s%s' %
                                                   (plat_name, so_suffix))
    _ed25519 = ffi.dlopen(os.path.abspath(lib_filename))
else:
    # set LIBRARY_PATH to pwd or use -L
    _ed25519 = ffi.verify(decl, libraries=["ed25519"]) # library_dirs = []

PUBLICKEYBYTES=32
SECRETKEYBYTES=64
SIGNATUREBYTES=64

def _ffi_tobytes(c, size):
    return bytes(ffi.buffer(c, size))

Keypair = namedtuple('Keypair', ('pk', 'sk'))

def crypto_sign_keypair(seed=None):
    """Return (public, private key) from a random seed, or os.urandom(32)"""
    pk = ffi.new('unsigned char[32]')
    sk = ffi.new('unsigned char[64]')
    if seed is None:
        seed = os.urandom(PUBLICKEYBYTES)
    else:
        warnings.warn("ed25519ll should choose random seed except in unit tests",
                      RuntimeWarning)
    if len(seed) != 32:
        raise ValueError("seed must be 32 random bytes or None")
    s = ffi.new('unsigned char[32]', map(ord, seed))
    rc = _ed25519.crypto_sign_keypair(pk, sk, s)
    if rc != 0:
        raise ValueError("rc != 0", rc)
    return Keypair(_ffi_tobytes(pk, len(pk)), _ffi_tobytes(sk, len(sk)))


def crypto_sign(msg, sk):
    """Return signature+message given message and secret key.
    The signature is the first SIGNATUREBYTES bytes of the return value.
    A copy of msg is in the remainder."""
    assert len(sk) == SECRETKEYBYTES
    sk = ffi.new('unsigned char[]', map(ord, sk))
    m = ffi.new('unsigned char[]', map(ord, msg))
    sig_and_msg = ffi.new('unsigned char[]', (len(msg) + SIGNATUREBYTES))
    # if I don't want a pointer, ffi.cast("unsigned long long", 42)
    sig_and_msg_len = ffi.new('unsigned long long')
    # sign a message
    rc = _ed25519.crypto_sign(sig_and_msg, sig_and_msg_len, m, len(m), sk)
    if rc != 0:
        raise ValueError("rc != 0", rc)
    return _ffi_tobytes(sig_and_msg, sig_and_msg_len[0])


def crypto_sign_open(signed, pk):
    """Return message given a signed message."""
    assert len(pk) == PUBLICKEYBYTES
    pk = ffi.new('unsigned char[]', map(ord, pk))
    sig_and_msg = ffi.new('unsigned char[]', map(ord, signed))
    msg = ffi.new('unsigned char[%d]' % (len(signed) + SIGNATUREBYTES))
    msg_len = ffi.new('unsigned long long', len(msg))
    rc = _ed25519.crypto_sign_open(msg, msg_len, sig_and_msg, len(sig_and_msg),
                                   pk)
    if rc != 0:
        raise ValueError("rc != 0", rc)
    return _ffi_tobytes(msg, msg_len[0])

