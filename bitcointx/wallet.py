# Copyright (C) 2012-2014 The python-bitcoinlib developers
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

"""Wallet-related functionality

Includes things like representing addresses and converting them to/from
scriptPubKeys; currently there is no actual wallet support implemented.
"""

# pylama:ignore=E501,E221

from abc import ABCMeta
from threading import local

import bitcointx
import bitcointx.base58
import bitcointx.bech32
import bitcointx.core

from bitcointx.core.util import (
    make_frontend_metaclass, set_frontend_class, CoinIdentityMeta
)
from bitcointx.core.key import (
    CPubKey, CKeyMixin, CExtKeyMixin, CExtPubKeyMixin
)
from bitcointx.core.script import (
    CScript, CBitcoinScript, CScriptInvalidError,
    OP_HASH160, OP_DUP, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL
)


_thread_local = local()
_frontend_metaclass = make_frontend_metaclass('_Wallet', _thread_local)


class CoinWalletIdentityMeta(CoinIdentityMeta, metaclass=ABCMeta):

    _frontend_metaclass = _frontend_metaclass

    @classmethod
    def _get_required_classes(cls):
        return (set((CCoinAddress, CBase58CoinAddress, CBech32CoinAddress,
                    P2SHCoinAddress, P2PKHCoinAddress,
                    P2WSHCoinAddress, P2WPKHCoinAddress,
                    CCoinKey, CCoinExtKey, CCoinExtPubKey)),
                set([CScript]))


class BitcoinWalletIdentityMeta(CoinWalletIdentityMeta):
    @classmethod
    def _get_extra_classmap(cls):
        return {CScript: CBitcoinScript}


class BitcoinTestnetWalletIdentityMeta(BitcoinWalletIdentityMeta):
    ...


class BitcoinRegtestWalletIdentityMeta(BitcoinWalletIdentityMeta):
    ...


class CCoinAddress(metaclass=_frontend_metaclass):
    pass


class CBase58CoinAddress(metaclass=_frontend_metaclass):
    pass


class P2SHCoinAddress(metaclass=_frontend_metaclass):
    pass


class P2PKHCoinAddress(metaclass=_frontend_metaclass):
    pass


class CBech32CoinAddress(metaclass=_frontend_metaclass):
    pass


class P2WSHCoinAddress(metaclass=_frontend_metaclass):
    pass


class P2WPKHCoinAddress(metaclass=_frontend_metaclass):
    pass


class CCoinAddressBase():

    def __new__(cls, s):
        for enc_class in (cls._concrete_class.CBech32CoinAddress,
                          cls._concrete_class.CBase58CoinAddress):
            try:
                return enc_class(s)
            except bitcointx.core.AddressEncodingError:
                pass

        raise CCoinAddressError(
            'Unrecognized encoding for {}' .format(cls.__name__))

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a subclass of CCoinAddress"""
        for enc_class in (cls._concrete_class.CBech32CoinAddress,
                          cls._concrete_class.CBase58CoinAddress):
            try:
                return enc_class.from_scriptPubKey(scriptPubKey)
            except CCoinAddressError:
                pass

        raise CCoinAddressError(
            'scriptPubKey is not in a recognized address format')


class CCoinAddressError(Exception):
    """Raised when an invalid coin address is encountered"""


class CBase58AddressError(CCoinAddressError):
    """Raised when an invalid base58-encoded address is encountered
    (error is not necessary related to encoding)"""


class CBech32AddressError(CCoinAddressError):
    """Raised when an invalid bech32-encoded address is encountered
    (error is not necessary related to encoding)"""


class P2SHCoinAddressError(CBase58AddressError):
    """Raised when an invalid P2SH address is encountered"""


class P2PKHCoinAddressError(CBase58AddressError):
    """Raised when an invalid P2PKH address is encountered"""


class P2WSHCoinAddressError(CBech32AddressError):
    """Raised when an invalid P2SH address is encountered"""


class P2WPKHCoinAddressError(CBech32AddressError):
    """Raised when an invalid P2PKH address is encountered"""


class CBech32CoinAddressCommon(bitcointx.bech32.CBech32Data):
    """A Bech32-encoded coin address"""

    _data_length = None
    _witness_version = None

    @classmethod
    def from_bytes(cls, witprog, witver=None):

        if cls._witness_version is None:
            assert witver is not None, \
                ("witver must be specified for {}.from_bytes()"
                 .format(cls.__name__))
            for candidate in (cls._concrete_class.P2WSHCoinAddress,
                              cls._concrete_class.P2WPKHCoinAddress):
                if len(witprog) == candidate._data_length and \
                        witver == candidate._witness_version:
                    break
            else:
                raise CBech32AddressError(
                    'witness program does not match any known Bech32 '
                    'address length')
        else:
            candidate = cls

        self = super(CBech32CoinAddressCommon, cls).from_bytes(
            bytes(witprog), witver=candidate._witness_version
        )
        self.__class__ = candidate

        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to subclass of CBech32CoinAddressCommon

        Returns a CBech32CoinAddressCommon subclass.
        If the scriptPubKey is not recognized CCoinAddressError will be raised.
        """
        for candidate in (cls._concrete_class.P2WSHCoinAddress,
                          cls._concrete_class.P2WPKHCoinAddress):
            try:
                return candidate.from_scriptPubKey(scriptPubKey)
            except CCoinAddressError:
                pass

        raise CBech32AddressError(
            'scriptPubKey not a valid bech32-encoded address')


class CBase58CoinAddressCommon(bitcointx.base58.CBase58PrefixedData):
    """A Base58-encoded coin address"""

    base58_prefix = b''

    @classmethod
    def from_bytes_with_prefix(cls, data):
        if not cls.base58_prefix:
            return cls.match_base58_classes(
                data, (cls._concrete_class.P2SHCoinAddress,
                       cls._concrete_class.P2PKHCoinAddress))
        return super(CBase58CoinAddressCommon, cls).from_bytes_with_prefix(data)

    @classmethod
    def from_bytes(cls, data):
        if not cls.base58_prefix:
            raise TypeError('from_bytes() method cannot be called on {}, '
                            'because base58_prefix is not defined for it'
                            .format(cls.__name__))
        return super(CBase58CoinAddressCommon, cls).from_bytes(data)

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a CCoinAddress

        Returns a CCoinAddress subclass:
            either subclass of P2SHCoinAddressCommon or
            subclass of P2PKHCoinAddressCommon.
            If the scriptPubKey is not recognized,
            CCoinAddressError will be raised.
        """
        for candidate in (cls._concrete_class.P2SHCoinAddress,
                          cls._concrete_class.P2PKHCoinAddress):
            try:
                return candidate.from_scriptPubKey(scriptPubKey)
            except CCoinAddressError:
                pass

        raise CBase58AddressError(
            'scriptPubKey not valid for base58-encoded address')


class P2SHCoinAddressCommon():
    _data_length = 20

    @classmethod
    def from_redeemScript(cls, redeemScript):
        """Convert a redeemScript to a P2SH address

        Convenience function: equivalent to P2SHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2SH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2sh():
            return cls.from_bytes(scriptPubKey[2:22])

        else:
            raise P2SHCoinAddressError('not a P2SH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return self._concrete_class.CScript([OP_HASH160, self, OP_EQUAL])

    def to_redeemScript(self):
        raise NotImplementedError("not enough data in p2sh address to reconstruct redeem script")


class P2PKHCoinAddressCommon():
    _data_length = 20

    @classmethod
    def from_pubkey(cls, pubkey, accept_invalid=False):
        """Create a P2PKH address from a pubkey

        Raises CCoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance;
        """
        if not isinstance(pubkey, (bytes, bytearray)):
            raise TypeError('pubkey must be bytes or bytearray instance; got %r'
                            % pubkey.__class__)

        if not accept_invalid:
            if not isinstance(pubkey, CPubKey):
                pubkey = CPubKey(pubkey)
            if not pubkey.is_fullyvalid():
                raise P2PKHCoinAddressError('invalid pubkey')

        pubkey_hash = bitcointx.core.Hash160(pubkey)
        return cls.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey, accept_non_canonical_pushdata=True, accept_bare_checksig=True):
        """Convert a scriptPubKey to a P2PKH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.

        accept_non_canonical_pushdata - Allow non-canonical pushes (default True)

        accept_bare_checksig          - Treat bare-checksig as P2PKH scriptPubKeys (default True)
        """
        if accept_non_canonical_pushdata:
            # Canonicalize script pushes

            # in case it's not a CScript instance yet
            scriptPubKey = cls._concrete_class.CScript(scriptPubKey)

            try:
                # canonicalize
                scriptPubKey = cls._concrete_class.CScript(tuple(scriptPubKey))
            except CScriptInvalidError:
                raise P2PKHCoinAddressError(
                    'not a P2PKH scriptPubKey: script is invalid')

        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(scriptPubKey[2:22])
        elif scriptPubKey.is_witness_v0_nested_keyhash():
            return cls.from_bytes(scriptPubKey[3:23])
        elif (len(scriptPubKey) == 25
                and scriptPubKey[0]  == OP_DUP
                and scriptPubKey[1]  == OP_HASH160
                and scriptPubKey[2]  == 0x14
                and scriptPubKey[23] == OP_EQUALVERIFY
                and scriptPubKey[24] == OP_CHECKSIG):
            return cls.from_bytes(scriptPubKey[3:23])

        elif accept_bare_checksig:
            pubkey = None

            # We can operate on the raw bytes directly because we've
            # canonicalized everything above.
            if (len(scriptPubKey) == 35  # compressed
                    and scriptPubKey[0]  == 0x21
                    and scriptPubKey[34] == OP_CHECKSIG):

                pubkey = scriptPubKey[1:34]

            elif (len(scriptPubKey) == 67  # uncompressed
                    and scriptPubKey[0] == 0x41
                    and scriptPubKey[66] == OP_CHECKSIG):

                pubkey = scriptPubKey[1:66]

            if pubkey is not None:
                return cls.from_pubkey(pubkey, accept_invalid=True)

        raise P2PKHCoinAddressError('not a P2PKH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return self._concrete_class.CScript([OP_DUP, OP_HASH160, self,
                                             OP_EQUALVERIFY, OP_CHECKSIG])

    def to_redeemScript(self):
        return self.to_scriptPubKey()


class P2WSHCoinAddressCommon():
    _data_length = 32
    _witness_version = 0

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2WSH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_scripthash():
            return cls.from_bytes(scriptPubKey[2:34])
        else:
            raise P2WSHCoinAddressError('not a P2WSH scriptPubKey')

    @classmethod
    def from_redeemScript(cls, redeemScript):
        """Convert a redeemScript to a P2WSH address

        Convenience function: equivalent to
        P2WSHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2wsh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2wsh_scriptPubKey())

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return self._concrete_class.CScript([0, self])

    def to_redeemScript(self):
        raise NotImplementedError(
            "not enough data in p2wsh address to reconstruct redeem script")


class P2WPKHCoinAddressCommon():
    _data_length = 20
    _witness_version = 0

    @classmethod
    def from_pubkey(cls, pubkey, accept_invalid=False):
        """Create a P2WPKH address from a pubkey

        Raises CCoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance;
        """
        if not isinstance(pubkey, (bytes, bytearray)):
            raise TypeError('pubkey must be bytes or bytearray instance; got %r'
                            % pubkey.__class__)

        if not accept_invalid:
            if not isinstance(pubkey, CPubKey):
                pubkey = CPubKey(pubkey)
            if not pubkey.is_fullyvalid():
                raise P2PKHCoinAddressError('invalid pubkey')

        pubkey_hash = bitcointx.core.Hash160(pubkey)
        return cls.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2WSH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(scriptPubKey[2:22])
        else:
            raise P2WPKHCoinAddressError('not a P2WPKH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return self._concrete_class.CScript([0, self])

    def to_redeemScript(self):
        return self._concrete_class.CScript([OP_DUP, OP_HASH160, self,
                                             OP_EQUALVERIFY, OP_CHECKSIG])


class CBitcoinAddress(CCoinAddressBase,
                      metaclass=BitcoinWalletIdentityMeta):
    ...


class CBitcoinTestnetAddress(CCoinAddressBase,
                             metaclass=BitcoinTestnetWalletIdentityMeta):
    ...


class CBitcoinRegtestAddress(CCoinAddressBase,
                             metaclass=BitcoinRegtestWalletIdentityMeta):
    ...


class CBase58BitcoinAddress(CBase58CoinAddressCommon, CBitcoinAddress):
    ...


class CBase58BitcoinTestnetAddress(CBase58CoinAddressCommon,
                                   CBitcoinTestnetAddress):
    ...


class CBase58BitcoinRegtestAddress(CBase58CoinAddressCommon,
                                   CBitcoinRegtestAddress):
    ...


class CBech32BitcoinAddress(CBech32CoinAddressCommon, CBitcoinAddress):
    bech32_hrp = 'bc'


class CBech32BitcoinTestnetAddress(CBech32CoinAddressCommon,
                                   CBitcoinTestnetAddress):
    bech32_hrp = 'tb'


class CBech32BitcoinRegtestAddress(CBech32CoinAddressCommon,
                                   CBitcoinTestnetAddress):
    bech32_hrp = 'bcrt'


class P2SHBitcoinAddress(P2SHCoinAddressCommon, CBase58BitcoinAddress):
    base58_prefix = bytes([5])


class P2PKHBitcoinAddress(P2PKHCoinAddressCommon, CBase58BitcoinAddress):
    base58_prefix = bytes([0])


class P2PKHBitcoinTestnetAddress(P2PKHCoinAddressCommon,
                                 CBase58BitcoinTestnetAddress):
    base58_prefix = bytes([111])


class P2SHBitcoinTestnetAddress(P2SHCoinAddressCommon,
                                CBase58BitcoinTestnetAddress):
    base58_prefix = bytes([196])


class P2PKHBitcoinRegtestAddress(P2PKHCoinAddressCommon,
                                 CBase58BitcoinRegtestAddress):
    base58_prefix = bytes([111])


class P2SHBitcoinRegtestAddress(P2SHCoinAddressCommon,
                                CBase58BitcoinRegtestAddress):
    base58_prefix = bytes([196])


class P2WSHBitcoinAddress(P2WSHCoinAddressCommon, CBech32BitcoinAddress):
    ...


class P2WPKHBitcoinAddress(P2WPKHCoinAddressCommon, CBech32BitcoinAddress):
    ...


class P2WSHBitcoinTestnetAddress(P2WSHCoinAddressCommon,
                                 CBech32BitcoinTestnetAddress):
    ...


class P2WPKHBitcoinTestnetAddress(P2WPKHCoinAddressCommon,
                                  CBech32BitcoinTestnetAddress):
    ...


class P2WSHBitcoinRegtestAddress(P2WSHCoinAddressCommon,
                                 CBech32BitcoinRegtestAddress):
    ...


class P2WPKHBitcoinRegtestAddress(P2WPKHCoinAddressCommon,
                                  CBech32BitcoinRegtestAddress):
    ...


class CCoinKey(metaclass=_frontend_metaclass):
    pass


class CBase58CoinKeyBase(bitcointx.base58.CBase58PrefixedData, CKeyMixin):
    """A base58-encoded secret key

    Attributes: (inherited from CKeyMixin):

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes

    is_compressed() - True if compressed

    Note that CBase58CoinKeyBase instance is 33 bytes long if compressed,
    32 bytes otherwise (due to WIF format that states b'\x01' should be
    appended for compressed keys).
    secret_bytes property is 32 bytes long in both cases.
    """

    @classmethod
    def from_bytes(cls, data):
        if len(data) > 33:
            raise ValueError('data size must not exceed 33 bytes')
        compressed = (len(data) > 32 and data[32] == 1)
        self = super(CBase58CoinKeyBase, cls).from_bytes(data)
        CKeyMixin.__init__(self, None, compressed=compressed)
        return self

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        self = super(CBase58CoinKeyBase, cls).from_bytes(secret + (b'\x01' if compressed else b''))
        CKeyMixin.__init__(self, None, compressed=compressed)
        return self

    def to_compressed(self):
        if self.is_compressed():
            return self
        return self.__class__.from_secret_bytes(self[:32], True)

    def to_uncompressed(self):
        if not self.is_compressed():
            return self
        return self.__class__.from_secret_bytes(self[:32], False)


class CBitcoinKey(CBase58CoinKeyBase,
                  metaclass=BitcoinWalletIdentityMeta):
    base58_prefix = bytes([128])


class CBitcoinSecret(CBitcoinKey):
    """this class is retained for backward compatibility.
    might be deprecated in the future."""


class CBitcoinTestnetKey(CBase58CoinKeyBase,
                         metaclass=BitcoinTestnetWalletIdentityMeta):
    base58_prefix = bytes([239])


class CBitcoinRegtestKey(CBase58CoinKeyBase,
                         metaclass=BitcoinRegtestWalletIdentityMeta):
    base58_prefix = bytes([239])


class CCoinExtKey(metaclass=_frontend_metaclass):
    pass


class CCoinExtPubKey(metaclass=_frontend_metaclass):
    pass


class CBase58CoinExtPubKeyBase(bitcointx.base58.CBase58PrefixedData,
                               CExtPubKeyMixin):

    def __init__(self, _s):
        assert isinstance(self, CExtPubKeyMixin)
        CExtPubKeyMixin.__init__(self, None)


class CBase58CoinExtKeyBase(bitcointx.base58.CBase58PrefixedData,
                            CExtKeyMixin):

    def __init__(self, _s):
        assert isinstance(self, CExtKeyMixin)
        CExtKeyMixin.__init__(self, None)

    @property
    def _xpub_class(self):
        return self._concrete_class.CCoinExtPubKey

    @property
    def _key_class(self):
        return self._concrete_class.CCoinKey


class CBitcoinExtPubKey(CBase58CoinExtPubKeyBase,
                        metaclass=BitcoinWalletIdentityMeta):
    """A base58-encoded extended public key

    Attributes (inherited from CExtPubKeyMixin):

    pub           - The corresponding CPubKey for extended pubkey
    """

    base58_prefix = b'\x04\x88\xB2\x1E'


class CBitcoinExtKey(CBase58CoinExtKeyBase,
                     metaclass=BitcoinWalletIdentityMeta):
    """A base58-encoded extended key

    Attributes (inherited from key mixin class):

    pub           - The corresponding CPubKey for extended pubkey
    priv          - The corresponding CBitcoinKey for extended privkey
    """

    base58_prefix = b'\x04\x88\xAD\xE4'


class CBitcoinTestnetExtPubKey(CBase58CoinExtPubKeyBase,
                               metaclass=BitcoinTestnetWalletIdentityMeta):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinTestnetExtKey(CBase58CoinExtKeyBase,
                            metaclass=BitcoinTestnetWalletIdentityMeta):
    base58_prefix = b'\x04\x35\x83\x94'


class CBitcoinRegtestExtPubKey(CBase58CoinExtPubKeyBase,
                               metaclass=BitcoinRegtestWalletIdentityMeta):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinRegtestExtKey(CBase58CoinKeyBase,
                            metaclass=BitcoinRegtestWalletIdentityMeta):
    base58_prefix = b'\x04\x35\x83\x94'


BitcoinWalletIdentityMeta.set_classmap({
    CCoinAddress: CBitcoinAddress,
    CBase58CoinAddress: CBase58BitcoinAddress,
    CBech32CoinAddress: CBech32BitcoinAddress,
    P2SHCoinAddress: P2SHBitcoinAddress,
    P2PKHCoinAddress: P2PKHBitcoinAddress,
    P2WSHCoinAddress: P2WSHBitcoinAddress,
    P2WPKHCoinAddress: P2WPKHBitcoinAddress,
    CCoinKey: CBitcoinKey,
    CCoinExtKey: CBitcoinExtKey,
    CCoinExtPubKey: CBitcoinExtPubKey,
})

BitcoinTestnetWalletIdentityMeta.set_classmap({
    CCoinAddress: CBitcoinTestnetAddress,
    CBase58CoinAddress: CBase58BitcoinTestnetAddress,
    CBech32CoinAddress: CBech32BitcoinTestnetAddress,
    P2SHCoinAddress: P2SHBitcoinTestnetAddress,
    P2PKHCoinAddress: P2PKHBitcoinTestnetAddress,
    P2WSHCoinAddress: P2WSHBitcoinTestnetAddress,
    P2WPKHCoinAddress: P2WPKHBitcoinTestnetAddress,
    CCoinKey: CBitcoinTestnetKey,
    CCoinExtKey: CBitcoinTestnetExtKey,
    CCoinExtPubKey: CBitcoinTestnetExtPubKey,
})

BitcoinRegtestWalletIdentityMeta.set_classmap({
    CCoinAddress: CBitcoinRegtestAddress,
    CBase58CoinAddress: CBase58BitcoinRegtestAddress,
    CBech32CoinAddress: CBech32BitcoinRegtestAddress,
    P2SHCoinAddress: P2SHBitcoinRegtestAddress,
    P2PKHCoinAddress: P2PKHBitcoinRegtestAddress,
    P2WSHCoinAddress: P2WSHBitcoinRegtestAddress,
    P2WPKHCoinAddress: P2WPKHBitcoinRegtestAddress,
    CCoinKey: CBitcoinRegtestKey,
    CCoinExtKey: CBitcoinRegtestExtKey,
    CCoinExtPubKey: CBitcoinRegtestExtPubKey,
})


def _SetWalletCoinIdentity(wallet_identity):
    for frontend, concrete in wallet_identity._clsmap.items():
        set_frontend_class(frontend, concrete, _thread_local)


def _SetChainParams(params):
    script_class_tx = \
        params.TRANSACTION_IDENTITY._clsmap[CScript]
    script_class_wlt = \
        params.TRANSACTION_IDENTITY._clsmap[CScript]
    assert script_class_tx == script_class_wlt,\
        ("script class for transaction identity and wallet identity "
         "must be the same")
    _SetWalletCoinIdentity(params.WALLET_IDENTITY)


_SetWalletCoinIdentity(BitcoinWalletIdentityMeta)


__all__ = (
    'CCoinAddressError',
    'P2SHCoinAddressError',
    'P2PKHCoinAddressError',
    'P2WSHCoinAddressError',
    'P2WPKHCoinAddressError',
    'CCoinAddress',
    'CBitcoinAddress',
    'CBitcoinTestnetAddress',
    'CBase58CoinAddressCommon',
    'CBech32CoinAddressCommon',
    'P2SHCoinAddressCommon',
    'P2PKHCoinAddressCommon',
    'P2WSHCoinAddressCommon',
    'P2WPKHCoinAddressCommon',
    'CBase58BitcoinAddress',
    'CBech32BitcoinAddress',
    'P2SHBitcoinAddress',
    'P2PKHBitcoinAddress',
    'P2WSHBitcoinAddress',
    'P2WPKHBitcoinAddress',
    'CBase58BitcoinTestnetAddress',
    'CBech32BitcoinTestnetAddress',
    'P2SHBitcoinTestnetAddress',
    'P2PKHBitcoinTestnetAddress',
    'P2WSHBitcoinTestnetAddress',
    'P2WPKHBitcoinTestnetAddress',
    'CBitcoinSecret',  # for backward compatibility
    'CBitcoinKey',
    'CBitcoinExtKey',
    'CBitcoinExtPubKey',
    'CBitcoinTestnetKey',
    'CBitcoinTestnetExtKey',
    'CBitcoinTestnetExtPubKey',
    'CBitcoinRegtestKey',
    'CBitcoinRegtestExtKey',
    'CBitcoinRegtestExtPubKey',
)
