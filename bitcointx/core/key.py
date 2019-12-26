# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
# Copyright (C) 2018-2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501,E261,E221

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""

import hmac
import struct
import ctypes
import ctypes.util
import hashlib
import warnings
from abc import abstractmethod
from typing import (
    TypeVar, Type, Union, Tuple, List, Sequence, Optional, Iterator, cast,
    Dict, Iterable
)

import bitcointx.core
from bitcointx.util import no_bool_use_as_property, ensure_isinstance
from bitcointx.core.secp256k1 import (
    _secp256k1, secp256k1_context_sign, secp256k1_context_verify,
    SIGNATURE_SIZE, COMPACT_SIGNATURE_SIZE,
    PUBLIC_KEY_SIZE, COMPRESSED_PUBLIC_KEY_SIZE,
    SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED,
    secp256k1_has_pubkey_recovery, secp256k1_has_ecdh,
    secp256k1_has_privkey_negate, secp256k1_has_pubkey_negate
)

BIP32_HARDENED_KEY_OFFSET = 0x80000000

T_CKeyBase = TypeVar('T_CKeyBase', bound='CKeyBase')
T_CExtKeyCommonBase = TypeVar('T_CExtKeyCommonBase', bound='CExtKeyCommonBase')
T_CExtKeyBase = TypeVar('T_CExtKeyBase', bound='CExtKeyBase')
T_CExtPubKeyBase = TypeVar('T_CExtPubKeyBase', bound='CExtPubKeyBase')
T_unbounded = TypeVar('T_unbounded')

try:
    _ssl: Optional[ctypes.CDLL] = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')
    if not getattr(_ssl, 'EC_KEY_new_by_curve_name', None):
        _ssl = None
except OSError:
    _ssl = None


class OpenSSLException(EnvironmentError):
    pass


class KeyDerivationFailException(RuntimeError):
    pass


# Thx to Sam Devlin for the ctypes magic 64-bit fix (FIXME: should this
# be applied to every OpenSSL call whose return type is a pointer?)
def _check_res_openssl_void_p(val, func, args): # type: ignore
    if val == 0:
        assert _ssl is not None
        errno = _ssl.ERR_get_error()
        errmsg = ctypes.create_string_buffer(120)
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        raise OpenSSLException(errno, str(errmsg.value))

    return ctypes.c_void_p(val)


if _ssl:
    _ssl.EC_KEY_new_by_curve_name.errcheck = _check_res_openssl_void_p  # type: ignore
    _ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
    _ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

    _ssl.ECDSA_SIG_free.restype = None
    _ssl.ECDSA_SIG_free.argtypes = [ctypes.c_void_p]

    _ssl.ERR_error_string_n.restype = None
    _ssl.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

    _ssl.ERR_get_error.restype = ctypes.c_ulong
    _ssl.ERR_get_error.argtypes = []

    _ssl.d2i_ECDSA_SIG.restype = ctypes.c_void_p
    _ssl.d2i_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

    _ssl.i2d_ECDSA_SIG.restype = ctypes.c_int
    _ssl.i2d_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    # this specifies the curve used with ECDSA.
    _NIDsecp256k1 = 714 # from openssl/obj_mac.h

    # test that OpenSSL supports secp256k1
    _ssl.EC_KEY_new_by_curve_name(_NIDsecp256k1)


class CKeyBase:
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes (needed because subclasses may have trailing data)

    is_compressed() - True if compressed

    """

    pub: 'CPubKey'

    def __init__(self, b: Optional[bytes], compressed: bool = True) -> None:
        raw_pubkey = ctypes.create_string_buffer(64)

        if len(self.secret_bytes) != 32:
            raise ValueError('secret data length too short')

        result = _secp256k1.secp256k1_ec_seckey_verify(
            secp256k1_context_sign, self.secret_bytes)

        if result != 1:
            assert result == 0
            raise ValueError('Invalid private key data')

        result = _secp256k1.secp256k1_ec_pubkey_create(
            secp256k1_context_sign, raw_pubkey, self.secret_bytes)

        if result != 1:
            assert result == 0
            raise ValueError('Cannot construct public key from private key')

        self.pub = CPubKey._from_ctypes_char_array(
            raw_pubkey, compressed=compressed)

    @no_bool_use_as_property
    def is_compressed(self) -> bool:
        return self.pub.is_compressed()

    @property
    def secret_bytes(self) -> bytes:
        assert isinstance(self, bytes)
        return self[:32]

    def sign(self, hash: Union[bytes, bytearray]) -> bytes:
        ensure_isinstance(hash, (bytes, bytearray), 'hash')
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        raw_sig = ctypes.create_string_buffer(64)
        result = _secp256k1.secp256k1_ecdsa_sign(
            secp256k1_context_sign, raw_sig, hash, self.secret_bytes, None, None)
        if 1 != result:
            assert(result == 0)
            raise RuntimeError('secp256k1_ecdsa_sign returned failure')
        sig_size0 = ctypes.c_size_t()
        sig_size0.value = SIGNATURE_SIZE
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _secp256k1.secp256k1_ecdsa_signature_serialize_der(
            secp256k1_context_sign, mb_sig, ctypes.byref(sig_size0), raw_sig)
        if 1 != result:
            assert(result == 0)
            raise RuntimeError('secp256k1_ecdsa_signature_parse_der returned failure')
        # secp256k1 creates signatures already in lower-S form, no further
        # conversion needed.
        return mb_sig.raw[:sig_size0.value]

    def sign_compact(self, hash: Union[bytes, bytearray]) -> Tuple[bytes, int]: # pylint: disable=redefined-builtin
        ensure_isinstance(hash, (bytes, bytearray), 'hash')
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        if not secp256k1_has_pubkey_recovery:
            raise RuntimeError('secp256k1 compiled without pubkey recovery functions. '
                               'sign_compact is not functional.')

        recoverable_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

        result = _secp256k1.secp256k1_ecdsa_sign_recoverable(
            secp256k1_context_sign, recoverable_sig, hash, self.secret_bytes, None, None)

        if 1 != result:
            assert(result == 0)
            raise RuntimeError('secp256k1_ecdsa_sign_recoverable returned failure')

        recid = ctypes.c_int()
        recid.value = 0
        output = ctypes.create_string_buffer(64)
        result = _secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            secp256k1_context_sign, output, ctypes.byref(recid), recoverable_sig)

        if 1 != result:
            assert(result == 0)
            raise RuntimeError('secp256k1_ecdsa_recoverable_signature_serialize_compact returned failure')

        return output.raw, recid.value

    def verify(self, hash: bytes, sig: bytes) -> bool:
        return self.pub.verify(hash, sig)

    def verify_nonstrict(self, hash: bytes, sig: bytes) -> bool:
        return self.pub.verify_nonstrict(hash, sig)

    def ECDH(self, pub: Optional['CPubKey'] = None) -> bytes:
        if not secp256k1_has_ecdh:
            raise RuntimeError(
                'secp256k1 compiled without ECDH shared secret computation functions. '
                'ECDH is not functional.')

        if pub is None:
            pub = self.pub

        if not pub.is_fullyvalid():
            raise ValueError('supplied pubkey is not valid')

        result_data = ctypes.create_string_buffer(32)
        ret = _secp256k1.secp256k1_ecdh(secp256k1_context_sign, result_data,
                                        pub._to_ctypes_char_array(), self,
                                        None, None)
        if 1 != ret:
            assert(ret == 0)
            raise RuntimeError('secp256k1_ecdh returned failure')
        return result_data.raw

    @classmethod
    def combine(cls: Type[T_CKeyBase], *privkeys: T_CKeyBase,
                compressed: bool = True) -> T_CKeyBase:
        if len(privkeys) <= 1:
            raise ValueError(
                'number of privkeys to combine must be more than one')
        if not all(isinstance(k, CKeyBase) for k in privkeys):
            raise ValueError(
                'each supplied privkey must be an instance of CKeyBase')

        result_data = ctypes.create_string_buffer((privkeys[0]).secret_bytes)
        for p in privkeys[1:]:
            ret = _secp256k1.secp256k1_ec_privkey_tweak_add(
                secp256k1_context_sign, result_data, p.secret_bytes)
            if ret != 1:
                assert ret == 0
                raise ValueError('Combining the keys failed')
        return cls.from_secret_bytes(result_data.raw[:32], compressed=compressed)

    @classmethod
    def add(cls: Type[T_CKeyBase], a: T_CKeyBase, b: T_CKeyBase) -> T_CKeyBase:
        if a.is_compressed() != b.is_compressed():
            raise ValueError("compressed attributes must match on "
                             "privkey addition/substraction")
        return cls.combine(a, b, compressed=a.is_compressed())

    @classmethod
    def sub(cls: Type[T_CKeyBase], a: T_CKeyBase, b: T_CKeyBase) -> T_CKeyBase:
        if a == b:
            raise ValueError('Values are equal, result would be zero, and '
                             'thus an invalid key.')
        return cls.add(a, b.negated())

    def negated(self: T_CKeyBase) -> T_CKeyBase:
        if not secp256k1_has_privkey_negate:
            raise RuntimeError(
                'secp256k1 does not export privkey negation function. '
                'You should use newer version of secp256k1 library')
        key_buf = ctypes.create_string_buffer(self.secret_bytes)
        ret = _secp256k1.secp256k1_ec_privkey_negate(secp256k1_context_sign, key_buf)
        if 1 != ret:
            assert(ret == 0)
            raise RuntimeError('secp256k1_ec_privkey_negate returned failure')
        return self.__class__.from_secret_bytes(key_buf.raw[:32], compressed=self.is_compressed())

    @classmethod
    def from_secret_bytes(cls: Type[T_CKeyBase],
                          secret: bytes, compressed: bool = True) -> T_CKeyBase:
        return cls(secret, compressed=compressed)

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        raise NotImplementedError('subclasses must override from_bytes()')


class CKey(bytes, CKeyBase):
    "Standalone privkey class"

    def __new__(cls: Type['CKey'], secret: bytes, compressed: bool = True
                ) -> 'CKey':
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        return super().__new__(cls, secret)  # type: ignore


T_CPubKey = TypeVar('T_CPubKey', bound='CPubKey')


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_nonempty()      - Corresponds to CPubKey.IsValid()

    is_fullyvalid() - Corresponds to CPubKey.IsFullyValid()

    is_compressed() - Corresponds to CPubKey.IsCompressed()

    key_id        - Hash160(pubkey)
    """

    _fullyvalid: bool
    key_id: bytes

    def __new__(cls: Type[T_CPubKey], buf: bytes = b'') -> T_CPubKey:
        self = super().__new__(cls, buf)  # type: ignore

        self._fullyvalid = False
        if self.is_nonempty():
            tmp_pub = ctypes.create_string_buffer(64)
            result = _secp256k1.secp256k1_ec_pubkey_parse(
                secp256k1_context_verify, tmp_pub, self, len(self))
            self._fullyvalid = (result == 1)

        self.key_id = bitcointx.core.Hash160(self)
        return cast(T_CPubKey, self)

    @classmethod
    def _from_ctypes_char_array(cls: Type[T_CPubKey],
                                raw_pubkey: 'ctypes.Array[ctypes.c_char]',
                                compressed: bool = True) -> T_CPubKey:
        if len(raw_pubkey) != 64:
            raise ValueError('raw pubkey must be 64 bytes')
        pub_size0 = ctypes.c_size_t()
        pub_size0.value = PUBLIC_KEY_SIZE
        pub = ctypes.create_string_buffer(pub_size0.value)

        _secp256k1.secp256k1_ec_pubkey_serialize(
            secp256k1_context_verify, pub, ctypes.byref(pub_size0), raw_pubkey,
            SECP256K1_EC_COMPRESSED if compressed else SECP256K1_EC_UNCOMPRESSED)

        return cls(pub.raw[:pub_size0.value])

    def _to_ctypes_char_array(self) -> 'ctypes.Array[ctypes.c_char]':
        assert self.is_fullyvalid()
        raw_pub = ctypes.create_string_buffer(64)
        result = _secp256k1.secp256k1_ec_pubkey_parse(
            secp256k1_context_verify, raw_pub, self, len(self))
        if 1 != result:
            assert(result == 0)
            raise RuntimeError('secp256k1_ec_pubkey_parse returned failure')
        return raw_pub

    @classmethod
    def recover_compact(cls: Type[T_CPubKey],
                        hash: bytes, sig: bytes) -> Optional[T_CPubKey]:
        """Recover a public key from a compact signature."""
        if len(sig) != COMPACT_SIGNATURE_SIZE:
            raise ValueError("Signature should be %d characters, not [%d]" % (COMPACT_SIGNATURE_SIZE, len(sig)))

        if not secp256k1_has_pubkey_recovery:
            raise RuntimeError('secp256k1 compiled without pubkey recovery functions. '
                               'recover_compact is not functional.')

        recid = (sig[0] - 27) & 3
        compressed = ((sig[0] - 27) & 4) != 0

        rec_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

        result = _secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_verify, rec_sig, sig[1:], recid)

        if result != 1:
            assert result == 0
            return None

        raw_pubkey = ctypes.create_string_buffer(64)

        result = _secp256k1.secp256k1_ecdsa_recover(
            secp256k1_context_verify, raw_pubkey, rec_sig, hash)

        if result != 1:
            assert result == 0
            return None

        return cls._from_ctypes_char_array(raw_pubkey, compressed=compressed)

    @no_bool_use_as_property
    def is_valid(self) -> bool:
        """Bitcoin Core has IsValid() and IsFullyValid() for CPubKey,
        but there is a danger that a developer would use is_valid() where
        they really meant is_fullyvalid(), and thus could pass invalid pubkeys
        potentially breaking some important checks. Better be safe and do not
        use confusing names - thus is_valid is deprecated and will be removed
        in the future."""
        warnings.warn(
            "CPubKey.is_valid() is deprecated due to possibility of confusion "
            "with CPubKey.is_fullyvalid(). CPubKey.is_valid() will be removed "
            "in the future. Please use CPubKey.is_nonempty() instead.",
            DeprecationWarning
        )
        return self.is_nonempty()

    @no_bool_use_as_property
    def is_nonempty(self) -> bool:
        return len(self) > 0

    @no_bool_use_as_property
    def is_fullyvalid(self) -> bool:
        return self._fullyvalid

    @no_bool_use_as_property
    def is_compressed(self) -> bool:
        return len(self) == COMPRESSED_PUBLIC_KEY_SIZE

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return '%s(%s)' % (self.__class__.__name__, super().__repr__())

    def verify(self, hash: bytes, sig: bytes) -> bool:
        """Verify a DER signature"""

        ensure_isinstance(sig, (bytes, bytearray), 'signature')
        ensure_isinstance(hash, (bytes, bytearray), 'hash')

        if not sig:
            return False

        if not self.is_fullyvalid():
            return False

        raw_sig = ctypes.create_string_buffer(64)
        result = _secp256k1.secp256k1_ecdsa_signature_parse_der(
            secp256k1_context_verify, raw_sig, sig, len(sig))

        if result != 1:
            assert result == 0
            return False

        _secp256k1.secp256k1_ecdsa_signature_normalize(
            secp256k1_context_verify, raw_sig, raw_sig)

        raw_pub = self._to_ctypes_char_array()
        result = _secp256k1.secp256k1_ecdsa_verify(
            secp256k1_context_verify, raw_sig, hash, raw_pub)

        if result != 1:
            assert result == 0
            return False

        return True

    def verify_nonstrict(self, hash: bytes, sig: bytes) -> bool:
        """Verify a non-strict DER signature"""

        if not _ssl:
            raise RuntimeError('openssl library is not available. verify_nonstrict is not functional.')

        ensure_isinstance(sig, (bytes, bytearray), 'signature')
        ensure_isinstance(hash, (bytes, bytearray), 'hash')

        if not sig:
            return False

        # bitcoind uses ecdsa_signature_parse_der_lax() to load signatures that
        # may be not properly encoded, but is still accepted by openssl.
        # it allows a strict subset of violations what OpenSSL will accept.
        # ecdsa_signature_parse_der_lax() is present in secp256k1 contrib/
        # directory, but is not compiled by default. Bundling it with this
        # library will mean that it have to use C compiler at build stage, and
        # I would like to avoid this build-dependency.
        #
        # secp256k1_ecdsa_verify won't accept encoding violations for
        # signatures, so instead of ecdsa_signature_parse_der_lax() we use
        # decode-openssl/encode-openssl/decode-secp256k cycle
        # this means that we allow all encoding violatons that openssl allows.
        #
        # extra encode/decode is wasteful, but the result is that verification
        # is still roughly 4 times faster than with openssl's ECDSA_verify()
        norm_sig = ctypes.c_void_p(0)
        result = _ssl.d2i_ECDSA_SIG(ctypes.byref(norm_sig), ctypes.byref(ctypes.c_char_p(sig)), len(sig))
        if not result:
            return False

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig, 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig)
            return False

        norm_der = ctypes.create_string_buffer(derlen)
        result = _ssl.i2d_ECDSA_SIG(norm_sig, ctypes.byref(ctypes.pointer(norm_der)))

        _ssl.ECDSA_SIG_free(norm_sig)

        if not result:
            return False

        return self.verify(hash, norm_der.raw)

    @classmethod
    def combine(cls: Type[T_CPubKey], *pubkeys: T_CPubKey,
                compressed: bool = True) -> T_CPubKey:
        if len(pubkeys) <= 1:
            raise ValueError(
                'number of pubkeys to combine must be more than one')
        if not all(isinstance(p, CPubKey) for p in pubkeys):
            raise ValueError(
                'each supplied pubkey must be an instance of CPubKey')

        pubkey_arr = (ctypes.c_char_p*len(pubkeys))()
        for i, p in enumerate(pubkeys):
            pubkey_arr[i] = bytes(p._to_ctypes_char_array())

        result_data = ctypes.create_string_buffer(64)
        ret = _secp256k1.secp256k1_ec_pubkey_combine(
            secp256k1_context_verify, result_data, pubkey_arr, len(pubkeys))
        if ret != 1:
            assert ret == 0
            raise ValueError('Combining the public keys failed')

        return cls._from_ctypes_char_array(result_data, compressed=compressed)

    def negated(self: T_CPubKey) -> T_CPubKey:
        if not secp256k1_has_pubkey_negate:
            raise RuntimeError(
                'secp256k1 does not export pubkey negation function. '
                'You should use newer version of secp256k1 library')
        pubkey_buf = self._to_ctypes_char_array()
        ret = _secp256k1.secp256k1_ec_pubkey_negate(secp256k1_context_verify, pubkey_buf)
        if 1 != ret:
            assert(ret == 0)
            raise RuntimeError('secp256k1_ec_pubkey_negate returned failure')
        return self.__class__._from_ctypes_char_array(
            pubkey_buf, compressed=self.is_compressed())

    @classmethod
    def add(cls: Type[T_CPubKey], a: T_CPubKey, b: T_CPubKey) -> T_CPubKey:
        if a.is_compressed() != b.is_compressed():
            raise ValueError(
                "compressed attributes must match on pubkey "
                "addition/substraction")
        return cls.combine(a, b, compressed=a.is_compressed())

    @classmethod
    def sub(cls: Type[T_CPubKey], a: T_CPubKey, b: T_CPubKey) -> T_CPubKey:
        if a == b:
            raise ValueError('Values are equal, result would be zero, and '
                             'thus an invalid public key.')
        return cls.add(a, b.negated())


class CExtKeyCommonBase:

    def _check_length(self) -> None:
        assert isinstance(self, bytes)
        if len(self) != 74:
            raise ValueError('Invalid length for extended key')

    @property
    @abstractmethod
    def pub(self) -> 'CPubKey':
        ...

    @property
    def depth(self) -> int:
        assert isinstance(self, bytes)
        return self[0]

    @property
    def parent_fp(self) -> bytes:
        assert isinstance(self, bytes)
        return self[1:5]

    @property
    def child_number(self) -> int:
        return int(struct.unpack(">L", self.child_number_bytes)[0])

    @property
    def child_number_bytes(self) -> bytes:
        assert isinstance(self, bytes)
        return self[5:9]

    @property
    def chaincode(self) -> bytes:
        assert isinstance(self, bytes)
        return self[9:41]

    @property
    def key_bytes(self) -> bytes:
        assert isinstance(self, bytes)
        return self[41:74]

    def derive_path(self: T_CExtKeyCommonBase,
                    path: Union[str, 'BIP32Path', Sequence[int]]
                    ) -> T_CExtKeyCommonBase:
        """Derive the key using the bip32 derivation path."""

        if not isinstance(path, BIP32Path):
            path = BIP32Path(path)

        # NOTE: empty path would mean we need to return master key
        # - there's no need for any derivation - you already have your key.
        # But if someone calls the derivation method, and there is no
        # actual derivation, that might mean that there is some error in
        # the code, and the path should be non-empty.
        # We choose to err on the safe side, and
        # raise ValueError on empty path
        if len(path) == 0:
            raise ValueError('derivation path is empty')

        xkey = self
        for n in path:
            xkey = xkey.derive(n)

        return xkey

    @property
    def fingerprint(self) -> bytes:
        return self.pub.key_id[:4]

    def derive(self: T_CExtKeyCommonBase, child_number: int) -> T_CExtKeyCommonBase:
        raise NotImplementedError('subclasses must override derive()')

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        raise NotImplementedError('subclasses must override from_bytes()')


class CExtKeyBase(CExtKeyCommonBase):
    """An encapsulated extended private key

    Attributes:

    priv          - The corresponding CKey for extended privkey
    pub           - shortcut property for priv.pub
    """

    priv: 'CKeyBase'

    @property
    def _key_class(self) -> Type['CKeyBase']:
        raise NotImplementedError

    @property
    def _xpub_class(self) -> Type['CExtPubKeyBase']:
        raise NotImplementedError

    def __init__(self, _b: Optional[bytes]) -> None:

        self._check_length()

        # NOTE: for xpubkey, first byte is pubkey prefix byte.
        # For xprivkey, this byte is supposed to be zero.
        if self.key_bytes[0] != 0:
            raise ValueError('The byte before private key data should be 0')
        raw_priv = self.key_bytes[1:]

        # NOTE: no need to make self.priv a @property method
        # because we need to pre-check if the privkey is valid now, anyway
        # CKey() will do this for us, and we can just set the priv attribute.
        self.priv = self._key_class.from_secret_bytes(raw_priv)

    @property
    def pub(self) -> CPubKey:
        return self.priv.pub

    @classmethod
    def from_seed(cls: Type[T_CExtKeyBase], seed: bytes) -> T_CExtKeyBase:
        if len(seed) not in (128//8, 256//8, 512//8):
            raise ValueError('Unexpected seed length')

        hmac_hash = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
        depth = 0
        parent_fp = child_number_packed = b'\x00\x00\x00\x00'
        privkey = hmac_hash[:32]
        chaincode = hmac_hash[32:]
        return cls.from_bytes(bytes([depth]) + parent_fp + child_number_packed + chaincode + bytes([0]) + privkey)

    def derive(self: T_CExtKeyBase, child_number: int) -> T_CExtKeyBase:
        if self.depth >= 255:
            raise ValueError('Maximum derivation path length is reached')

        if (child_number >> 32) != 0:
            raise ValueError('Child number is too big')

        depth = self.depth + 1

        child_number_packed = struct.pack(">L", child_number)

        if (child_number >> 31) == 0:
            bip32_hash = hmac.new(self.chaincode, self.pub + child_number_packed,
                                  hashlib.sha512).digest()
        else:
            bip32_hash = hmac.new(self.chaincode,
                                  bytes([0]) + self.priv.secret_bytes + child_number_packed,
                                  hashlib.sha512).digest()

        chaincode = bip32_hash[32:]

        child_privkey = ctypes.create_string_buffer(self.priv.secret_bytes, size=32)

        result = _secp256k1.secp256k1_ec_privkey_tweak_add(
            secp256k1_context_sign, child_privkey, bip32_hash)

        if result != 1:
            assert result == 0
            raise KeyDerivationFailException('extended privkey derivation failed')

        cls = self.__class__
        return cls.from_bytes(bytes([depth]) + self.fingerprint
                              + child_number_packed + chaincode
                              + bytes([0]) + child_privkey.raw)

    def neuter(self) -> 'CExtPubKeyBase':
        return self._xpub_class.from_bytes(
            bytes([self.depth]) + self.parent_fp + self.child_number_bytes + self.chaincode + self.pub)


class CExtPubKeyBase(CExtKeyCommonBase):
    """An encapsulated extended public key

    Attributes:

    pub              - The corresponding CPubKey for extended pubkey
    derivation_info  - The information about derivation of this extended pubkey
                       from the master (Optional, has to be set explicitly)
    """

    derivation_info: Optional['KeyDerivationInfo']

    def __init__(self, _b: Optional[bytes]) -> None:

        self._check_length()

        self._pub = CPubKey(self.key_bytes)
        if not self.pub.is_fullyvalid():
            raise ValueError('pubkey part of xpubkey is not valid')

        self.derivation_info = None

    @property
    def pub(self) -> CPubKey:
        return self._pub

    def derive(self: T_CExtPubKeyBase, child_number: int) -> T_CExtPubKeyBase:
        if (child_number >> 31) != 0:
            if (child_number >> 32) != 0:
                raise ValueError('Child number is too big')
            else:
                raise ValueError('Hardened derivation not possible')
        if self.depth >= 255:
            raise ValueError('Maximum derivation path length is reached')

        assert self.pub.is_fullyvalid()
        assert self.pub.is_compressed()

        child_number_packed = struct.pack(">L", child_number)

        depth = self.depth + 1
        bip32_hash = hmac.new(self.chaincode, self.pub + child_number_packed,
                              hashlib.sha512).digest()
        chaincode = bip32_hash[32:]

        raw_pub = self.pub._to_ctypes_char_array()

        result = _secp256k1.secp256k1_ec_pubkey_tweak_add(
            secp256k1_context_verify, raw_pub, bip32_hash)

        if result != 1:
            assert result == 0
            raise KeyDerivationFailException('extended pubkey derivation failed')

        child_pubkey_size0 = ctypes.c_size_t()
        child_pubkey_size0.value = COMPRESSED_PUBLIC_KEY_SIZE
        child_pubkey = ctypes.create_string_buffer(child_pubkey_size0.value)

        result = _secp256k1.secp256k1_ec_pubkey_serialize(
            secp256k1_context_verify, child_pubkey, ctypes.byref(child_pubkey_size0), raw_pub,
            SECP256K1_EC_COMPRESSED)

        if 1 != result:
            assert(result == 0)
            raise RuntimeError('secp256k1_ec_pubkey_serialize returned failure')

        cls = self.__class__
        return cls.from_bytes(bytes([depth]) + self.fingerprint
                              + child_number_packed + chaincode
                              + child_pubkey.raw)


T_CExtPubKey = TypeVar('T_CExtPubKey', bound='CExtPubKey')


class CExtPubKey(bytes, CExtPubKeyBase):
    "Standalone extended pubkey class"

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        # We cannot annotate cls with a bounded type here, because
        # there would be conflicts with CBase58Data, etc.
        # But with unbounded type, mypy cannot know if the classs
        # creation can have arguments.
        return cls(data)  # type: ignore


T_CExtKey = TypeVar('T_CExtKey', bound='CExtKey')


class CExtKey(bytes, CExtKeyBase):
    "Standalone extended key class"

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        # We cannot annotate cls with a bounded type here, because
        # there would be conflicts with CBase58Data, etc.
        # But with unbounded type, mypy cannot know if the classs
        # creation can have arguments.
        return cls(data)  # type: ignore

    @property
    def _key_class(self) -> Type[CKey]:
        return CKey

    @property
    def _xpub_class(self) -> Type[CExtPubKey]:
        return CExtPubKey


class BIP32Path:

    HARDENED_MARKERS = ("'", "h")

    __slots__ = ['_indexes', '_hardened_marker']

    _indexes: Tuple[int, ...]
    _hardened_marker: str

    def __init__(self, path: Union[str, 'BIP32Path', Sequence[int]],
                 hardened_marker: Optional[str] = None):
        if hardened_marker is not None:
            if hardened_marker not in self.__class__.HARDENED_MARKERS:
                raise ValueError('unsupported hardened_marker')

        indexes: Sequence[int]

        if isinstance(path, str):
            indexes, hardened_marker = self._parse_string(
                path, hardened_marker=hardened_marker)
        elif isinstance(path, BIP32Path):
            if hardened_marker is None:
                hardened_marker = path._hardened_marker
            indexes = path._indexes
            # we cannot just use _indexes if it is mutalbe,
            # assert that it is a tuple, so if the _indexes attr will
            # ever become mutable, this would be cathed by tests
            assert isinstance(indexes, tuple)
        else:
            indexes = path

        if len(indexes) > 255:
            raise ValueError('derivation path longer than 255 elements')

        for i, n in enumerate(indexes):
            ensure_isinstance(n, int, f'element at position {i} in the path')
            self._check_bip32_index_bounds(n, allow_hardened=True)

        if hardened_marker is None:
            hardened_marker = self.__class__.HARDENED_MARKERS[0]

        self._indexes = tuple(indexes)
        self._hardened_marker = hardened_marker

    def __str__(self) -> str:
        if len(self._indexes) == 0:
            return 'm'

        return 'm/%s' % '/'.join('%u' % n if n < BIP32_HARDENED_KEY_OFFSET
                                 else
                                 '%u%s' % (n - BIP32_HARDENED_KEY_OFFSET,
                                           self._hardened_marker)
                                 for n in self._indexes)

    def __len__(self) -> int:
        return len(self._indexes)

    def __getitem__(self, key: int) -> int:
        return self._indexes[key]

    def __iter__(self) -> Iterator[int]:
        return (n for n in self._indexes)

    def _check_bip32_index_bounds(self, n: int, allow_hardened: bool = False
                                  ) -> None:
        if n < 0:
            raise ValueError('derivation index cannot be negative')

        limit = 0xFFFFFFFF if allow_hardened else BIP32_HARDENED_KEY_OFFSET-1

        if n > limit:
            raise ValueError(
                'derivation index cannot be > {}' .format(limit))

    def _parse_string(self, path: str, hardened_marker: Optional[str] = None
                      ) -> Tuple[List[int], Optional[str]]:
        """Parse bip32 derivation path.
        returns a tuple (list_of_indexes, actual_hardened_marker).
        hardened indexes will have BIP32_HARDENED_KEY_OFFSET added to them."""

        assert isinstance(path, str)

        if path == 'm':
            return [], hardened_marker
        elif not path.startswith('m/'):
            raise ValueError('derivation path does not start with "m/" '
                             'and not equal to "m"')

        if path.endswith('/'):
            raise ValueError('derivation path must not end with "/"')

        indexes = []

        expected_marker = hardened_marker

        for pos, elt in enumerate(path[2:].split('/')):
            if elt == '':
                # m/// is probably a result of the error, where indexes
                # for some reason was empty strings. Be strict and not allow that.
                raise ValueError('duplicate slashes are not allowed')

            c = elt
            hardened = 0
            if c[-1] in self.__class__.HARDENED_MARKERS:
                if expected_marker is None:
                    expected_marker = c[-1]
                elif expected_marker != c[-1]:
                    raise ValueError(
                        'Unexpected hardened marker: "{}" {}, but got {}'
                        .format(expected_marker,
                                ('seen in the path previously'
                                 if hardened_marker is None
                                 else 'was specified'),
                                c[-1]))
                hardened = BIP32_HARDENED_KEY_OFFSET
                c = c[:-1]

            # If element is not valid int, ValueError will be raised
            n = int(c)

            self._check_bip32_index_bounds(n, allow_hardened=False)

            indexes.append(n + hardened)

        return indexes, expected_marker


T_KeyDerivationInfo = TypeVar('T_KeyDerivationInfo', bound='KeyDerivationInfo')


class KeyDerivationInfo:
    master_fingerprint: bytes
    path: BIP32Path
    pubkey: Optional[CPubKey]

    def __init__(self,
                 master_fingerprint: bytes,
                 path: BIP32Path,
                 pubkey: Optional[CPubKey] = None
                 ) -> None:
        ensure_isinstance(master_fingerprint, bytes, 'master key fingerprint')
        ensure_isinstance(path, BIP32Path, 'bip32 path')
        if pubkey:
            ensure_isinstance(pubkey, CPubKey, 'pubkey')
        if len(master_fingerprint) != 4:
            raise ValueError('Fingerprint should be 4 bytes in length')
        self.master_fingerprint = master_fingerprint
        self.path = path
        self.pubkey = pubkey

    def clone(self: T_KeyDerivationInfo) -> T_KeyDerivationInfo:
        return self.__class__(
            master_fingerprint=self.master_fingerprint,
            path=BIP32Path(path=self.path),
            pubkey=(None if self.pubkey is None else CPubKey(self.pubkey)))


T_KeyStoreKeyArg = Union[CKeyBase, CPubKey, CExtKeyBase, CExtPubKeyBase]
T_KeyStore = TypeVar('T_KeyStore', bound='KeyStore')


class KeyStore:
    # KeyStore can store pubkeys and xpubkeys. This can be used, for example,
    # for output checks to determine the change output when you do not
    # have the privkeys
    _xprivkeys: Dict[bytes, CExtKeyBase]
    _xpubkeys: Dict[bytes, Dict[Tuple[int, ...], CExtPubKeyBase]]
    _privkeys: Dict[bytes, CKeyBase]
    _pubkeys: Dict[bytes, CPubKey]

    def __init__(self, *args: T_KeyStoreKeyArg) -> None:
        self._privkeys = {}
        self._pubkeys = {}
        self._xpubkeys = {}
        self._xprivkeys = {}

        for k in args:
            self.add_key(k)

    @classmethod
    def from_iterable(cls: Type[T_KeyStore],
                      iterable: Iterable[T_KeyStoreKeyArg]
                      ) -> T_KeyStore:
        kstore = cls()
        for k in iterable:
            kstore.add_key(k)
        return kstore

    def add_key(self, k: T_KeyStoreKeyArg) -> None:
        if isinstance(k, CKeyBase):
            self._privkeys[k.pub.key_id] = k
        elif isinstance(k, CPubKey):
            self._pubkeys[k.key_id] = k
        elif isinstance(k, CExtKeyBase):
            self._xprivkeys[k.fingerprint] = k
        elif isinstance(k, CExtPubKeyBase):
            if not k.derivation_info:
                raise ValueError('xpub must have derivation_info assigned')
            derinfo = k.derivation_info
            ensure_isinstance(derinfo, KeyDerivationInfo,
                              'derivation_info of xpub')
            if derinfo.master_fingerprint not in self._xpubkeys:
                self._xpubkeys[derinfo.master_fingerprint] = {}
            self._xpubkeys[
                derinfo.master_fingerprint
            ][derinfo.path._indexes] = k
        else:
            raise ValueError(
                f'object supplied to add_key is of type '
                f'{k.__class__.__name__}, which is not recognized key type')

    def remove_key(self, k: T_KeyStoreKeyArg) -> None:
        if isinstance(k, CKeyBase):
            if k.pub.key_id in self._privkeys:
                self._privkeys.pop(k.pub.key_id)
        elif isinstance(k, CPubKey):
            if k.key_id in self._pubkeys:
                self._pubkeys.pop(k.key_id)
        elif isinstance(k, CExtKeyBase):
            if k.fingerprint in self._privkeys:
                self._xprivkeys.pop(k.fingerprint)
        elif isinstance(k, tuple):
            if len(k) != 2:
                raise ValueError(
                    'invalid tuple supplied, expected length 2')
            orig_xpub, derinfo = k
            ensure_isinstance(derinfo, KeyDerivationInfo,
                              'derivation info for xpub')
            if derinfo.master_fingerprint not in self._xpubkeys:
                return
            xpub_dict = self._xpubkeys[derinfo.master_fingerprint]
            indexes = derinfo.path._indexes
            if indexes in xpub_dict:
                if orig_xpub is not None \
                        and orig_xpub != xpub_dict[indexes]:
                    raise ValueError(
                        'xpub does not match the one stored for specified '
                        'derivation info')
                xpub_dict.pop(indexes)
        else:
            raise ValueError('unrecognized argument type')

    def get_privkey(self, key_id: bytes,
                    derivation: Optional[
                        Dict[bytes, T_KeyDerivationInfo]
                    ] = None
                    ) -> Optional[CKeyBase]:
        ensure_isinstance(key_id, bytes, 'key_id')
        ensure_isinstance(derivation, dict, 'key_id to derivation dict')
        if len(key_id) != 20:
            raise ValueError('invalid length for key_id, expected to be 20')

        if key_id in self._privkeys:
            return self._privkeys[key_id]

        if not derivation:
            return None

        derinfo = derivation.get(key_id)

        if not derinfo:
            return None

        ensure_isinstance(derinfo, KeyDerivationInfo, 'derivation info')

        if derinfo.pubkey is not None and derinfo.pubkey.key_id != key_id:
            raise AssertionError(
                'key_id for pubkey found in supplied derivation dict '
                'must match supplied key_id')

        if derinfo.master_fingerprint not in self._xprivkeys:
            return None

        xpriv = self._xprivkeys[derinfo.master_fingerprint]
        xpriv = xpriv.derive_path(derinfo.path)
        if xpriv.priv.pub.key_id != key_id:
            raise ValueError(
                'supplied key_id does not match the key derived using '
                'supplied derivation')
        return xpriv.priv

    def get_pubkey(self, key_id: bytes,
                   derivation: Optional[
                       Dict[bytes, T_KeyDerivationInfo]
                   ] = None
                   ) -> Optional[CPubKey]:
        ensure_isinstance(key_id, bytes, 'key_id')
        ensure_isinstance(derivation, dict, 'key_id to derivation dict')
        if len(key_id) != 20:
            raise ValueError('invalid length for key_id, expected to be 20')

        if key_id in self._pubkeys:
            return self._pubkeys[key_id]

        if not derivation:
            return None

        derinfo = derivation.get(key_id)

        if not derinfo:
            return None

        ensure_isinstance(derinfo, KeyDerivationInfo, 'derivation info')

        if derinfo.master_fingerprint in self._xpubkeys:
            xpub_dict = self._xpubkeys[derinfo.master_fingerprint]
            for indexes, xpub in xpub_dict.items():
                if derinfo.path._indexes[:len(indexes)] == indexes:
                    tail = derinfo.path._indexes[len(indexes):]
                    if all(idx < BIP32_HARDENED_KEY_OFFSET for idx in tail):
                        xpub = xpub.derive_path(tail)
                        if xpub.pub.key_id != key_id:
                            raise ValueError(
                                'supplied key_id does not match the '
                                'pubkey derived using supplied derivation')
                        return xpub.pub

        priv = self.get_privkey(key_id, derivation)
        if priv:
            return priv.pub

        return None


__all__ = (
    'CKey',
    'CPubKey',
    'CExtKey',
    'CExtPubKey',
    'CKeyBase',
    'CExtKeyBase',
    'CExtPubKeyBase',
    'BIP32Path',
    'KeyDerivationInfo',
    'KeyStore'
)
