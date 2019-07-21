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

import bitcointx
import bitcointx.base58
import bitcointx.bech32
import bitcointx.core

from bitcointx.util import (
    ClassMappingDispatcher, activate_class_dispatcher, dispatcher_mapped_list
)
from bitcointx.core.key import (
    CPubKey, CKeyMixin, CExtKeyMixin, CExtPubKeyMixin
)
from bitcointx.core.script import (
    CScript, OP_HASH160, OP_DUP, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL
)


class WalletClassDispatcher(ClassMappingDispatcher, identity='wallet',
                            no_direct_use=True):
    ...


class WalletBitcoinClassDispatcher(WalletClassDispatcher):
    ...


class WalletBitcoinTestnetClassDispatcher(WalletBitcoinClassDispatcher):
    ...


class WalletBitcoinRegtestClassDispatcher(WalletBitcoinClassDispatcher):
    ...


class WalletCoinClass(metaclass=WalletClassDispatcher):
    ...


class WalletBitcoinClass(WalletCoinClass,
                         metaclass=WalletBitcoinClassDispatcher):
    ...


class WalletBitcoinTestnetClass(WalletBitcoinClass,
                                metaclass=WalletBitcoinTestnetClassDispatcher):
    ...


class WalletBitcoinRegtestClass(WalletBitcoinClass,
                                metaclass=WalletBitcoinRegtestClassDispatcher):
    ...


class CCoinAddress(WalletCoinClass):

    def __new__(cls, s):
        recognized_encoding = set()
        enc_class_set = dispatcher_mapped_list(cls)
        for enc_class in enc_class_set:
            try:
                return enc_class(s)
            except CCoinAddressError:
                recognized_encoding.add(enc_class)
            except bitcointx.core.AddressDataEncodingError:
                pass

        if recognized_encoding:
            raise CCoinAddressError(
                'Correct encoding for any of {}, but not correct format'
                .format(recognized_encoding))

        raise CCoinAddressError(
            'Unrecognized encoding for any of {}'.format(enc_class_set))

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a subclass of CCoinAddress"""
        for candidate in dispatcher_mapped_list(cls):
            try:
                return candidate.from_scriptPubKey(scriptPubKey)
            except CCoinAddressError:
                pass

        raise CCoinAddressError(
            'scriptPubKey is not in a recognized address format')


class CCoinAddressError(Exception):
    """Raised when an invalid coin address is encountered"""


class CBase58AddressError(CCoinAddressError):
    """Raised when an invalid base58-encoded address is encountered"""


class CBech32AddressError(CCoinAddressError):
    """Raised when an invalid bech32-encoded address is encountered"""


class P2SHCoinAddressError(CBase58AddressError):
    """Raised when an invalid P2SH address is encountered"""


class P2PKHCoinAddressError(CBase58AddressError):
    """Raised when an invalid P2PKH address is encountered"""


class P2WSHCoinAddressError(CBech32AddressError):
    """Raised when an invalid P2SH address is encountered"""


class P2WPKHCoinAddressError(CBech32AddressError):
    """Raised when an invalid P2PKH address is encountered"""


class CBech32CoinAddress(bitcointx.bech32.CBech32Data, CCoinAddress):
    """A Bech32-encoded coin address"""

    _data_length = None
    _witness_version = None

    @classmethod
    def from_bytes(cls, witprog, witver=None):
        if cls._witness_version is None:
            assert witver is not None, \
                ("witver must be specified for {}.from_bytes()"
                 .format(cls.__name__))
            for candidate in dispatcher_mapped_list(cls):
                if len(witprog) == candidate._data_length and \
                        witver == candidate._witness_version:
                    break
            else:
                raise CBech32AddressError(
                    'witness program does not match any known Bech32 '
                    'address length or version')
        else:
            candidate = cls

        if len(witprog) != candidate._data_length or \
                (witver is not None and witver != candidate._witness_version):
            raise CBech32AddressError(
                'witness program does not match {}'
                'expected length or version'.format(cls.__name__))

        self = super(CBech32CoinAddress, cls).from_bytes(
            bytes(witprog), witver=candidate._witness_version
        )
        self.__class__ = candidate

        return self


class CBase58CoinAddress(bitcointx.base58.CBase58PrefixedData, CCoinAddress):
    """A Base58-encoded coin address"""

    base58_prefix = b''

    @classmethod
    def from_bytes_with_prefix(cls, data):
        if not cls.base58_prefix:
            candidates = dispatcher_mapped_list(cls)
            return cls.match_base58_classes(data, candidates)
        return super(CBase58CoinAddress, cls).from_bytes_with_prefix(data)

    @classmethod
    def from_bytes(cls, data):
        if not cls.base58_prefix:
            raise TypeError('from_bytes() method cannot be called on {}, '
                            'because base58_prefix is not defined for it'
                            .format(cls.__name__))
        return super(CBase58CoinAddress, cls).from_bytes(data)


class P2SHCoinAddress(CBase58CoinAddress, next_dispatch_final=True):
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
        return CScript([OP_HASH160, self, OP_EQUAL])

    def to_redeemScript(self):
        raise NotImplementedError("not enough data in p2sh address to reconstruct redeem script")


class P2PKHCoinAddress(CBase58CoinAddress, next_dispatch_final=True):
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
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2PKH address
        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2pkh():
            return cls.from_bytes(scriptPubKey[3:23])

        raise P2PKHCoinAddressError('not a P2PKH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return CScript([OP_DUP, OP_HASH160, self, OP_EQUALVERIFY, OP_CHECKSIG])

    def to_redeemScript(self):
        return self.to_scriptPubKey()

    @classmethod
    def from_redeemScript(cls, redeemScript):
        return cls.from_scriptPubKey(redeemScript)


class P2WSHCoinAddress(CBech32CoinAddress, next_dispatch_final=True):
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
        return CScript([0, self])

    def to_redeemScript(self):
        raise NotImplementedError(
            "not enough data in p2wsh address to reconstruct redeem script")


class P2WPKHCoinAddress(CBech32CoinAddress, next_dispatch_final=True):
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
        """Convert a scriptPubKey to a P2WPKH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(scriptPubKey[2:22])
        else:
            raise P2WPKHCoinAddressError('not a P2WPKH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return CScript([0, self])

    def to_redeemScript(self):
        return CScript([OP_DUP, OP_HASH160, self,
                        OP_EQUALVERIFY, OP_CHECKSIG])

    @classmethod
    def from_redeemScript(cls, redeemScript):
        """Convert a redeemScript to a P2WPKH address

        Convenience function: equivalent to
        P2WPKHHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2wpkh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2wpkh_scriptPubKey())


class CBitcoinAddress(CCoinAddress, WalletBitcoinClass):
    ...


class CBitcoinTestnetAddress(CCoinAddress, WalletBitcoinTestnetClass):
    ...


class CBitcoinRegtestAddress(CCoinAddress, WalletBitcoinRegtestClass):
    ...


class CBase58BitcoinAddress(CBase58CoinAddress, CBitcoinAddress):
    ...


class CBase58BitcoinTestnetAddress(CBase58CoinAddress, CBitcoinTestnetAddress):
    ...


class CBase58BitcoinRegtestAddress(CBase58CoinAddress, CBitcoinRegtestAddress):
    ...


class CBech32BitcoinAddress(CBech32CoinAddress, CBitcoinAddress):
    bech32_hrp = 'bc'


class CBech32BitcoinTestnetAddress(CBech32CoinAddress,
                                   CBitcoinTestnetAddress):
    bech32_hrp = 'tb'


class CBech32BitcoinRegtestAddress(CBech32CoinAddress,
                                   CBitcoinRegtestAddress):
    bech32_hrp = 'bcrt'


class P2SHBitcoinAddress(P2SHCoinAddress, CBase58BitcoinAddress):
    base58_prefix = bytes([5])


class P2PKHBitcoinAddress(P2PKHCoinAddress, CBase58BitcoinAddress):
    base58_prefix = bytes([0])


class P2PKHBitcoinTestnetAddress(P2PKHCoinAddress,
                                 CBase58BitcoinTestnetAddress):
    base58_prefix = bytes([111])


class P2SHBitcoinTestnetAddress(P2SHCoinAddress,
                                CBase58BitcoinTestnetAddress):
    base58_prefix = bytes([196])


class P2PKHBitcoinRegtestAddress(P2PKHCoinAddress,
                                 CBase58BitcoinRegtestAddress):
    base58_prefix = bytes([111])


class P2SHBitcoinRegtestAddress(P2SHCoinAddress,
                                CBase58BitcoinRegtestAddress):
    base58_prefix = bytes([196])


class P2WSHBitcoinAddress(P2WSHCoinAddress, CBech32BitcoinAddress):
    ...


class P2WPKHBitcoinAddress(P2WPKHCoinAddress, CBech32BitcoinAddress):
    ...


class P2WSHBitcoinTestnetAddress(P2WSHCoinAddress,
                                 CBech32BitcoinTestnetAddress):
    ...


class P2WPKHBitcoinTestnetAddress(P2WPKHCoinAddress,
                                  CBech32BitcoinTestnetAddress):
    ...


class P2WSHBitcoinRegtestAddress(P2WSHCoinAddress,
                                 CBech32BitcoinRegtestAddress):
    ...


class P2WPKHBitcoinRegtestAddress(P2WPKHCoinAddress,
                                  CBech32BitcoinRegtestAddress):
    ...


class CCoinKey(bitcointx.base58.CBase58PrefixedData, CKeyMixin,
               WalletCoinClass, next_dispatch_final=True):
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
        self = super(CCoinKey, cls).from_bytes(data)
        CKeyMixin.__init__(self, None, compressed=compressed)
        return self

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        self = super(CCoinKey, cls).from_bytes(secret + (b'\x01' if compressed else b''))
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


class CBitcoinKey(CCoinKey, WalletBitcoinClass):
    base58_prefix = bytes([128])


class CBitcoinSecret(CBitcoinKey, variant_of=CBitcoinKey):
    """a backwards-compatibility class for CBitcoinKey"""
    ...


class CBitcoinTestnetKey(CCoinKey, WalletBitcoinTestnetClass):
    base58_prefix = bytes([239])


class CBitcoinRegtestKey(CCoinKey, WalletBitcoinRegtestClass):
    base58_prefix = bytes([239])


class CCoinExtPubKey(bitcointx.base58.CBase58PrefixedData, CExtPubKeyMixin,
                     WalletCoinClass, next_dispatch_final=True):

    def __init__(self, _s):
        assert isinstance(self, CExtPubKeyMixin)
        CExtPubKeyMixin.__init__(self, None)


class CCoinExtKey(bitcointx.base58.CBase58PrefixedData, CExtKeyMixin,
                  WalletCoinClass, next_dispatch_final=True):

    def __init__(self, _s):
        assert isinstance(self, CExtKeyMixin)
        CExtKeyMixin.__init__(self, None)

    @property
    def _xpub_class(self):
        return dispatcher_mapped_list(CCoinExtPubKey)[0]

    @property
    def _key_class(self):
        return dispatcher_mapped_list(CCoinKey)[0]


class CBitcoinExtPubKey(CCoinExtPubKey, WalletBitcoinClass):
    """A base58-encoded extended public key

    Attributes (inherited from CExtPubKeyMixin):

    pub           - The corresponding CPubKey for extended pubkey
    """

    base58_prefix = b'\x04\x88\xB2\x1E'


class CBitcoinExtKey(CCoinExtKey, WalletBitcoinClass):
    """A base58-encoded extended key

    Attributes (inherited from key mixin class):

    pub           - The corresponding CPubKey for extended pubkey
    priv          - The corresponding CBitcoinKey for extended privkey
    """

    base58_prefix = b'\x04\x88\xAD\xE4'


class CBitcoinTestnetExtPubKey(CCoinExtPubKey, WalletBitcoinTestnetClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinTestnetExtKey(CCoinExtKey, WalletBitcoinTestnetClass):
    base58_prefix = b'\x04\x35\x83\x94'


class CBitcoinRegtestExtPubKey(CCoinExtPubKey, WalletBitcoinRegtestClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinRegtestExtKey(CCoinExtKey, WalletBitcoinRegtestClass):
    base58_prefix = b'\x04\x35\x83\x94'


def _SetChainParams(params):
    activate_class_dispatcher(params.WALLET_DISPATCHER)


activate_class_dispatcher(WalletBitcoinClassDispatcher)

__all__ = (
    'CCoinAddressError',
    'P2SHCoinAddressError',
    'P2PKHCoinAddressError',
    'P2WSHCoinAddressError',
    'P2WPKHCoinAddressError',
    'CCoinAddress',
    'CBitcoinAddress',
    'CBitcoinTestnetAddress',
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
    'CBitcoinKey',
    'CBitcoinSecret',  # backwards-compatible naming for CBitcoinKey
    'CBitcoinExtKey',
    'CBitcoinExtPubKey',
    'CBitcoinTestnetKey',
    'CBitcoinTestnetExtKey',
    'CBitcoinTestnetExtPubKey',
    'CBitcoinRegtestKey',
    'CBitcoinRegtestExtKey',
    'CBitcoinRegtestExtPubKey',
    'WalletClassDispatcher',
    'WalletCoinClass',
)
