About Ed25519
=============

Ed25519 is a public-key signature system with several attractive features 
including:

* Fast single-signature verification.
* Very fast signing.
* Fast key generation.
* High security level.
* Small signatures. Signatures fit into 64 bytes.
* Small keys. Public keys consume only 32 bytes. 

This text abridged from http://ed25519.cr.yp.to/.

About ed25519ll
===============

ed25519ll is a low-level wrapper for the Ed25519 public key signature
system. It uses Extension() to compile a shared library that is not a
Python extension module, and then uses ctypes to talk to the library. With
luck it will only be necessary to compile ed25519ll once for each
platform, reusing its shared library across Python versions.

This wrapper currently exposes the supercop-ref10 implementation of
Ed25519, on my 2.6GHz Athlon achieving about 7200 signatures/second/core
and 2900 verifications/second/core including the wrapper overhead.

This wrapper also contains a reasonably performat pure-Python
fallback. Unlike the reference implementation, the Python implementation
does not contain protection against timing attacks.

Example::
    
    import ed25519ll
    msg = b"The rain in Spain stays mainly on the plain"
    kp = ed25519ll.crypto_sign_keypair()
    signed = ed25519ll.crypto_sign(msg, kp.sk) 
    verified = ed25519ll.crypto_sign_open(signed, kp.vk)
    assert verified == msg  # but ValueError is raised for bad signatures 

API
===

ed25519ll exposes the supercop-ref10 API rather directly. All messages and keys
are binary strings (bytes() or Python 2 str()). Signed messages consist of the
64 signature bytes concatenated with the message.

``Keypair()`` is a named tuple ``(vk, sk)`` of the verifying key (32 bytes) and
the signing key (64 bytes). The second half of the signing key is a copy of the
verifying key.

``crypto_sign_keypair()`` returns a new ``Keypair()``. ``os.urandom()`` is used
as the random seed. This operation is about as fast as signing.

``crypto_sign(msg, sk)`` takes a message (any binary string) and a 64-byte 
signing key (from crypto_sign_keypair()) and returns a signed message.

``crypto_sign_open(signed, vk)`` takes a signed message (64 byte signature + 
message) and the corresponding 32-byte verifying key and returns a copy of the
message without the attached signature. ``ValueError`` is raised for invalid
signatures.
