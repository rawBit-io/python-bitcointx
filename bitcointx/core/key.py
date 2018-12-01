# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""
import ctypes
import ctypes.util
import sys
from os import urandom

_bchr = chr
_bord = ord
if sys.version > '3':
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

_ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')
_libsecp256k1 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('secp256k1'))

class OpenSSLException(EnvironmentError):
    pass

# Thx to Sam Devlin for the ctypes magic 64-bit fix (FIXME: should this
# be applied to every OpenSSL call whose return type is a pointer?)
def _check_res_void_p(val, func, args): # pylint: disable=unused-argument
    if val == 0:
        errno = _ssl.ERR_get_error()
        errmsg = ctypes.create_string_buffer(120)
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        raise OpenSSLException(errno, str(errmsg.value))

    return ctypes.c_void_p(val)

_ssl.BN_bin2bn.restype = ctypes.c_void_p
_ssl.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]

_ssl.BN_new.errcheck = _check_res_void_p
_ssl.BN_new.restype = ctypes.c_void_p
_ssl.BN_new.argtypes = []

_ssl.BN_CTX_free.restype = None
_ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_new.errcheck = _check_res_void_p
_ssl.BN_CTX_new.restype = ctypes.c_void_p
_ssl.BN_CTX_new.argtypes = []

_ssl.EC_KEY_free.restype = None
_ssl.EC_KEY_free.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_new_by_curve_name.errcheck = _check_res_void_p
_ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
_ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

_ssl.EC_KEY_get0_group.restype = ctypes.c_void_p
_ssl.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_set_conv_form.restype = None
_ssl.EC_KEY_set_conv_form.argtypes = [ctypes.c_void_p, ctypes.c_int]

_ssl.EC_KEY_set_private_key.restype = ctypes.c_int
_ssl.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_KEY_set_public_key.restype = ctypes.c_int
_ssl.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_free.restype = None
_ssl.EC_POINT_free.argtypes = [ctypes.c_void_p]

_ssl.EC_POINT_new.errcheck = _check_res_void_p
_ssl.EC_POINT_new.restype = ctypes.c_void_p
_ssl.EC_POINT_new.argtypes = [ctypes.c_void_p]

_ssl.EC_POINT_mul.restype = ctypes.c_int
_ssl.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.ECDSA_SIG_free.restype = None
_ssl.ECDSA_SIG_free.argtypes = [ctypes.c_void_p]

_ssl.ERR_error_string_n.restype = None
_ssl.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

_ssl.ERR_get_error.restype = ctypes.c_ulong
_ssl.ERR_get_error.argtypes = []

_ssl.d2i_ECDSA_SIG.restype = ctypes.c_void_p
_ssl.d2i_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.d2i_ECPrivateKey.restype = ctypes.c_void_p
_ssl.d2i_ECPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.i2d_ECDSA_SIG.restype = ctypes.c_int
_ssl.i2d_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.i2d_ECPrivateKey.restype = ctypes.c_int
_ssl.i2d_ECPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.i2o_ECPublicKey.restype = ctypes.c_void_p
_ssl.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.o2i_ECPublicKey.restype = ctypes.c_void_p
_ssl.o2i_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.BN_num_bits.restype = ctypes.c_int
_ssl.BN_num_bits.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_get0_private_key.restype = ctypes.c_void_p

# this specifies the curve used with ECDSA.
_NID_secp256k1 = 714 # from openssl/obj_mac.h

# test that OpenSSL supports secp256k1
_ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)

SECP256K1_CONTEXT_SIGN = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_VERIFY = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)

SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)


_libsecp256k1.secp256k1_context_create.restype = ctypes.c_void_p
_libsecp256k1.secp256k1_context_create.errcheck = _check_res_void_p
_libsecp256k1.secp256k1_context_create.argtypes = [ctypes.c_uint]

_libsecp256k1.secp256k1_context_randomize.restype = ctypes.c_int
_libsecp256k1.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

_libsecp256k1.secp256k1_ecdsa_sign.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

_libsecp256k1.secp256k1_ecdsa_signature_serialize_der.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p]

_libsecp256k1.secp256k1_ecdsa_sign_recoverable.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_sign_recoverable.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

_libsecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]

_libsecp256k1.secp256k1_ecdsa_recover.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_recover.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

_libsecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]

_libsecp256k1.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
_libsecp256k1.secp256k1_ec_pubkey_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_uint]

_libsecp256k1.secp256k1_ecdsa_signature_parse_der.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]

_libsecp256k1.secp256k1_ecdsa_signature_normalize.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_signature_normalize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

_libsecp256k1.secp256k1_ecdsa_verify.restype = ctypes.c_int
_libsecp256k1.secp256k1_ecdsa_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

_libsecp256k1_context_sign = _libsecp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
assert _libsecp256k1_context_sign is not None
_libsecp256k1_context_verify = _libsecp256k1.secp256k1_context_create(SECP256K1_CONTEXT_VERIFY)
assert _libsecp256k1_context_verify is not None

_libsecp256k1_seed = urandom(32)
assert(_libsecp256k1.secp256k1_context_randomize(_libsecp256k1_context_sign, _libsecp256k1_seed) == 1)


class CECKey:
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

    def __del__(self):
        if _ssl:
            _ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = _ssl.BN_bin2bn(secret, 32, _ssl.BN_new())
        group = _ssl.EC_KEY_get0_group(self.k)
        pub_key = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        if not _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        _ssl.EC_KEY_set_private_key(self.k, priv_key)
        _ssl.EC_KEY_set_public_key(self.k, pub_key)
        _ssl.EC_POINT_free(pub_key)
        _ssl.BN_CTX_free(ctx)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = _ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        _ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = _ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        _ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_privkey(self):
        bn = _ssl.EC_KEY_get0_private_key(self.k)
        bn = ctypes.c_void_p(bn)
        size = (_ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(int(size))
        _ssl.BN_bn2bin(bn, mb)
        return mb.raw.rjust(32, b'\x00')

    def sign(self, hash):
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        raw_sig = ctypes.create_string_buffer(64)
        result = _libsecp256k1.secp256k1_ecdsa_sign(
            _libsecp256k1_context_sign, raw_sig, hash, self.get_raw_privkey(), None, None)
        assert 1 == result
        sig_size0 = ctypes.c_size_t()
        sig_size0.value = 75
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _libsecp256k1.secp256k1_ecdsa_signature_serialize_der(
            _libsecp256k1_context_sign, mb_sig, ctypes.byref(sig_size0), raw_sig)
        assert 1 == result
        # libsecp256k1 creates signatures already in lower-S form, no further
        # conversion needed.
        return mb_sig.raw[:sig_size0.value]

    def sign_compact(self, hash): # pylint: disable=redefined-builtin
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        recoverable_sig = ctypes.create_string_buffer(65)

        result = _libsecp256k1.secp256k1_ecdsa_sign_recoverable(
            _libsecp256k1_context_sign, recoverable_sig, hash, self.get_raw_privkey(), None, None)

        assert 1 == result

        recid = ctypes.c_int()
        recid.value = 0
        output = ctypes.create_string_buffer(64)
        result = _libsecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            _libsecp256k1_context_sign, output, ctypes.byref(recid), recoverable_sig)

        assert 1 == result

        return bytes(output), recid.value

    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        """Verify a DER signature"""
        if not sig:
          return False

        # bitcoind uses ecdsa_signature_parse_der_lax() to load signatures that
        # may be not properly encoded, but is still accepted by openssl.
        # it allows a strict subset of violations what OpenSSL will accept.
        # ecdsa_signature_parse_der_lax() is present in libsecp256k1 contrib/
        # directory, but is not compiled by default. Bundling it with this
        # library will mean that it have to use C compiler at build stage, and
        # I would like to avoid this build-dependency.
        #
        # secp256k1_ecdsa_verify won't accept encoding violations for
        # signatures, so instead of ecdsa_signature_parse_der_lax() we use
        # decode-openssl/encode-openssl/decode-libsecp256k cycle
        # this means that we allow all encoding violatons that openssl allows.
        #
        # extra encode/decode is wasteful, but the result is that verification
        # is still roughly 4 times faster than with openssl's ECDSA_verify()
        norm_sig = ctypes.c_void_p(0)
        _ssl.d2i_ECDSA_SIG(ctypes.byref(norm_sig), ctypes.byref(ctypes.c_char_p(sig)), len(sig))

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig, 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig)
            return False

        norm_der = ctypes.create_string_buffer(derlen)
        _ssl.i2d_ECDSA_SIG(norm_sig, ctypes.byref(ctypes.pointer(norm_der)))
        _ssl.ECDSA_SIG_free(norm_sig)

        raw_sig = ctypes.create_string_buffer(64)
        result = _libsecp256k1.secp256k1_ecdsa_signature_parse_der(
            _libsecp256k1_context_verify, raw_sig, norm_der, len(norm_der))

        if result != 1:
            return False

        _libsecp256k1.secp256k1_ecdsa_signature_normalize(
            _libsecp256k1_context_verify, raw_sig, raw_sig)

        unparsed_pub = self.get_pubkey()
        pub = ctypes.create_string_buffer(64)

        result = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _libsecp256k1_context_verify, pub, unparsed_pub, len(unparsed_pub))

        if result != 1:
            return False

        result = _libsecp256k1.secp256k1_ecdsa_verify(
            _libsecp256k1_context_verify, raw_sig, hash, pub)

        return result == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        _ssl.EC_KEY_set_conv_form(self.k, form)


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()

    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()

    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) is not None
        return self

    @classmethod
    def recover_compact(cls, hash, sig): # pylint: disable=redefined-builtin
        """Recover a public key from a compact signature."""
        if len(sig) != 65:
            raise ValueError("Signature should be 65 characters, not [%d]" % (len(sig), ))

        recid = (_bord(sig[0]) - 27) & 3
        compressed = (_bord(sig[0]) - 27) & 4 != 0

        rec_sig = ctypes.create_string_buffer(65)

        result = _libsecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
            _libsecp256k1_context_verify, rec_sig, sig[1:], recid)

        if result != 1:
            return False

        pubkey = ctypes.create_string_buffer(64)

        result = _libsecp256k1.secp256k1_ecdsa_recover(
            _libsecp256k1_context_verify, pubkey, rec_sig, hash)

        if result != 1:
            return False

        pub_size0 = ctypes.c_size_t()
        pub_size0.value = 65
        pub = ctypes.create_string_buffer(pub_size0.value)

        _libsecp256k1.secp256k1_ec_pubkey_serialize(
            _libsecp256k1_context_verify, pub, ctypes.byref(pub_size0), pubkey,
            SECP256K1_EC_COMPRESSED if compressed else SECP256K1_EC_UNCOMPRESSED)

        return CPubKey(bytes(pub)[:pub_size0.value])

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        # Always have represent as b'<secret>' so test cases don't have to
        # change for py2/3
        if sys.version > '3':
            return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())
        else:
            return '%s(b%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())

__all__ = (
        'CECKey',
        'CPubKey',
)
