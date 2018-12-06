# Copyright (C) 2012-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
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
import bitcointx.core.key
import bitcointx.core.script as script


class CBitcoinAddress(object):

    def __new__(cls, s):
        try:
            return CBech32BitcoinAddress(s)
        except bitcointx.bech32.Bech32Error:
            pass

        try:
            return CBase58BitcoinAddress(s)
        except bitcointx.base58.Base58Error:
            pass

        raise CBitcoinAddressError('Unrecognized encoding for bitcoin address')

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a subclass of CBitcoinAddress"""
        try:
            return CBech32BitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return CBase58BitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey is not in a recognized address format')


class CBitcoinAddressError(Exception):
    """Raised when an invalid Bitcoin address is encountered"""


class CBech32BitcoinAddress(bitcointx.bech32.CBech32Data, CBitcoinAddress):
    """A Bech32-encoded Bitcoin address"""

    @classmethod
    def from_bytes(cls, witver, witprog):

        assert witver == 0
        self = super(CBech32BitcoinAddress, cls).from_bytes(
            witver,
            bytes(witprog)
        )

        if len(self) == 32:
            self.__class__ = P2WSHBitcoinAddress
        elif len(self) == 20:
            self.__class__ = P2WPKHBitcoinAddress
        else:
            raise CBitcoinAddressError('witness program does not match any known segwit address format')

        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a CBech32BitcoinAddress

        Returns a CBech32BitcoinAddress subclass, either P2WSHBitcoinAddress or
        P2WPKHBitcoinAddress. If the scriptPubKey is not recognized
        CBitcoinAddressError will be raised.
        """
        try:
            return P2WSHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return P2WPKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey not a valid bech32-encoded address')


class CBase58BitcoinAddress(bitcointx.base58.CBase58Data, CBitcoinAddress):
    """A Base58-encoded Bitcoin address"""

    @classmethod
    def from_bytes(cls, data, nVersion):
        alt_script_prefixes = getattr(bitcointx.params, 'ALT_BASE58_SCRIPT_PREFIXES', None)
        if alt_script_prefixes and nVersion in alt_script_prefixes.values():
            nVersion = bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR']

        self = super(CBase58BitcoinAddress, cls).from_bytes(data, nVersion)

        if nVersion == bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR']:
            self.__class__ = P2SHBitcoinAddress

        elif nVersion == bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR']:
            self.__class__ = P2PKHBitcoinAddress

        else:
            raise CBitcoinAddressError('Version %d not a recognized Bitcoin Address' % nVersion)

        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a CBitcoinAddress

        Returns a CBitcoinAddress subclass, either P2SHBitcoinAddress or
        P2PKHBitcoinAddress. If the scriptPubKey is not recognized
        CBitcoinAddressError will be raised.
        """
        try:
            return P2SHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey not a valid base58-encoded address')


class P2SHBitcoinAddress(CBase58BitcoinAddress):
    @classmethod
    def from_bytes(cls, data, nVersion=None):
        if nVersion is None:
            nVersion = bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR']

        elif nVersion != bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR']:
            raise ValueError('nVersion incorrect for P2SH address: got %d; expected %d' %
                             (nVersion, bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR']))

        return super(P2SHBitcoinAddress, cls).from_bytes(data, nVersion)

    @classmethod
    def from_redeemScript(cls, redeemScript):
        """Convert a redeemScript to a P2SH address

        Convenience function: equivalent to P2SHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2SH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2sh():
            return cls.from_bytes(scriptPubKey[2:22], bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR'])

        else:
            raise CBitcoinAddressError('not a P2SH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.nVersion == bitcointx.params.BASE58_PREFIXES['SCRIPT_ADDR']
        return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

    def to_redeemScript(self):
        return self.to_scriptPubKey()


class P2PKHBitcoinAddress(CBase58BitcoinAddress):
    @classmethod
    def from_bytes(cls, data, nVersion=None):
        if nVersion is None:
            nVersion = bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR']

        elif nVersion != bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR']:
            raise ValueError('nVersion incorrect for P2PKH address: got %d; expected %d' %
                             (nVersion, bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR']))

        return super(P2PKHBitcoinAddress, cls).from_bytes(data, nVersion)

    @classmethod
    def from_pubkey(cls, pubkey, accept_invalid=False):
        """Create a P2PKH bitcoin address from a pubkey

        Raises CBitcoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance;
        """
        if not isinstance(pubkey, bytes):
            raise TypeError('pubkey must be bytes instance; got %r' % pubkey.__class__)

        if not accept_invalid:
            if not isinstance(pubkey, bitcointx.core.key.CPubKey):
                pubkey = bitcointx.core.key.CPubKey(pubkey)
            if not pubkey.is_fullyvalid:
                raise CBitcoinAddressError('invalid pubkey')

        pubkey_hash = bitcointx.core.Hash160(pubkey)
        return P2PKHBitcoinAddress.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey, accept_non_canonical_pushdata=True, accept_bare_checksig=True):
        """Convert a scriptPubKey to a P2PKH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.

        accept_non_canonical_pushdata - Allow non-canonical pushes (default True)

        accept_bare_checksig          - Treat bare-checksig as P2PKH scriptPubKeys (default True)
        """
        if accept_non_canonical_pushdata:
            # Canonicalize script pushes
            scriptPubKey = script.CScript(scriptPubKey)  # in case it's not a CScript instance yet

            try:
                scriptPubKey = script.CScript(tuple(scriptPubKey))  # canonicalize
            except bitcointx.core.script.CScriptInvalidError:
                raise CBitcoinAddressError('not a P2PKH scriptPubKey: script is invalid')

        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(scriptPubKey[2:22], bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR'])
        elif scriptPubKey.is_witness_v0_nested_keyhash():
            return cls.from_bytes(scriptPubKey[3:23], bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR'])
        elif (len(scriptPubKey) == 25
                and scriptPubKey[0]  == script.OP_DUP
                and scriptPubKey[1]  == script.OP_HASH160
                and scriptPubKey[2]  == 0x14
                and scriptPubKey[23] == script.OP_EQUALVERIFY
                and scriptPubKey[24] == script.OP_CHECKSIG):
            return cls.from_bytes(scriptPubKey[3:23], bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR'])

        elif accept_bare_checksig:
            pubkey = None

            # We can operate on the raw bytes directly because we've
            # canonicalized everything above.
            if (len(scriptPubKey) == 35  # compressed
                    and scriptPubKey[0]  == 0x21
                    and scriptPubKey[34] == script.OP_CHECKSIG):

                pubkey = scriptPubKey[1:34]

            elif (len(scriptPubKey) == 67  # uncompressed
                    and scriptPubKey[0] == 0x41
                    and scriptPubKey[66] == script.OP_CHECKSIG):

                pubkey = scriptPubKey[1:65]

            if pubkey is not None:
                return cls.from_pubkey(pubkey, accept_invalid=True)

        raise CBitcoinAddressError('not a P2PKH scriptPubKey')

    def to_scriptPubKey(self, nested=False):
        """Convert an address to a scriptPubKey"""
        assert self.nVersion == bitcointx.params.BASE58_PREFIXES['PUBKEY_ADDR']
        return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

    def to_redeemScript(self):
        return self.to_scriptPubKey()


class P2WSHBitcoinAddress(CBech32BitcoinAddress):

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2WSH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_scripthash():
            return cls.from_bytes(0, scriptPubKey[2:34])
        else:
            raise CBitcoinAddressError('not a P2WSH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.witver == 0
        return script.CScript([0, self])

    def to_redeemScript(self):
        return NotImplementedError("not enough data in p2wsh address to reconstruct redeem script")


class P2WPKHBitcoinAddress(CBech32BitcoinAddress):

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2WSH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(0, scriptPubKey[2:22])
        else:
            raise CBitcoinAddressError('not a P2WSH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.witver == 0
        return script.CScript([0, self])

    def to_redeemScript(self):
        return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])


class CBitcoinSecretError(bitcointx.base58.Base58Error):
    pass


class CBitcoinSecret(bitcointx.base58.CBase58Data, bitcointx.core.key.CKey):
    """A base58-encoded secret key"""

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        self = cls.from_bytes(secret + (b'\x01' if compressed else b''),
                              bitcointx.params.BASE58_PREFIXES['SECRET_KEY'])
        self.__init__(None)
        return self

    def __init__(self, s):
        if self.nVersion != bitcointx.params.BASE58_PREFIXES['SECRET_KEY']:
            raise CBitcoinSecretError('Not a base58-encoded secret key: got nVersion=%d; expected nVersion=%d' %
                                      (self.nVersion, bitcointx.params.BASE58_PREFIXES['SECRET_KEY']))

        bitcointx.core.key.CKey.__init__(self, self[0:32], len(self) > 32 and self[32] == 1)


class CBitcoinExtKey(bitcointx.base58.CBase58RawData):

    @classmethod
    def from_bytes(cls, data):
        prefix = bitcointx.params.BASE58_PREFIXES['EXTENDED_PRIVKEY']
        if data[:4] != prefix:
            raise ValueError('incorrect version bytes for xprivkey: {}, expected {}'
                             .format(bitcointx.core.b2x(data[:4]),
                                     bitcointx.core.b2x(bitcointx.params.BASE58_PREFIXES['EXTENDED_PRIVKEY'])))

        self = super(CBitcoinExtKey, cls).from_bytes(data)

        self.xpriv = bitcointx.core.key.CExtKey(data[4:])

        return self

    @classmethod
    def from_xpriv(cls, xpriv):
        assert isinstance(xpriv, bitcointx.core.key.CExtKey)
        prefix = bitcointx.params.BASE58_PREFIXES['EXTENDED_PRIVKEY']
        return cls.from_bytes(prefix + xpriv)

    def to_bytes(self):
        """Convert to bytes instance

        Note that it's the data represented that is converted; the checkum and
        nVersion is not included.
        """
        prefix = bitcointx.params.BASE58_PREFIXES['EXTENDED_PRIVKEY']
        return prefix + self


class CBitcoinExtPubKey(bitcointx.base58.CBase58RawData):
    @classmethod
    def from_bytes(cls, data):
        prefix = bitcointx.params.BASE58_PREFIXES['EXTENDED_PUBKEY']
        if data[:4] != prefix:
            raise ValueError('incorrect version bytes for xpubkey: {}, expected {}'
                             .format(bitcointx.core.b2x(data[:4]),
                                     bitcointx.core.b2x(bitcointx.params.BASE58_PREFIXES['EXTENDED_PUBKEY'])))

        self = super(CBitcoinExtPubKey, cls).from_bytes(data)

        self.xpub = bitcointx.core.key.CExtPubKey(data[4:])

        return self

    @classmethod
    def from_xpub(cls, xpub):
        assert isinstance(xpub, bitcointx.core.key.CExtPubKey)
        prefix = bitcointx.params.BASE58_PREFIXES['EXTENDED_PUBKEY']
        return cls.from_bytes(prefix + xpub)

    def to_key(self):
        return self.xpub

    def to_bytes(self):
        """Convert to bytes instance

        Note that it's the data represented that is converted; the checkum and
        nVersion is not included.
        """
        prefix = bitcointx.params.BASE58_PREFIXES['EXTENDED_PUBKEY']
        return prefix + self

__all__ = (
        'CBitcoinAddressError',
        'CBitcoinAddress',
        'CBase58BitcoinAddress',
        'CBech32BitcoinAddress',
        'P2SHBitcoinAddress',
        'P2PKHBitcoinAddress',
        'P2WSHBitcoinAddress',
        'P2WPKHBitcoinAddress',
        'CBitcoinSecretError',
        'CBitcoinSecret',
        'CBitcoinExtKey',
        'CBitcoinExtPubKey',
)
