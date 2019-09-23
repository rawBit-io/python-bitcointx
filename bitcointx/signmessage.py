# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from bitcointx.core.key import CPubKey, CKeyBase
from bitcointx.core.serialize import ImmutableSerializable
from bitcointx.wallet import P2PKHCoinAddress
import bitcointx
import base64

# pylama:ignore=E501


def VerifyMessage(address: P2PKHCoinAddress, message: 'BitcoinMessage',
                  sig: str) -> bool:
    sig_bytes = base64.b64decode(sig)
    hash = message.GetHash()

    pubkey = CPubKey.recover_compact(hash, sig_bytes)

    if pubkey is None:
        return False

    return str(P2PKHCoinAddress.from_pubkey(pubkey)) == str(address)


def SignMessage(key: CKeyBase, message: 'BitcoinMessage') -> bytes:
    sig, i = key.sign_compact(message.GetHash())

    meta = 27 + i
    if key.is_compressed():
        meta += 4

    return base64.b64encode(bytes([meta]) + sig)


class BitcoinMessage(ImmutableSerializable):
    __slots__ = ['magic', 'message']

    message: bytes
    magic: bytes

    def __init__(self, message: str = "",
                 magic: str = "Bitcoin Signed Message:\n") -> None:
        object.__setattr__(self, 'message', message.encode("utf-8"))
        object.__setattr__(self, 'magic', magic.encode("utf-8"))

    @classmethod
    def stream_deserialize(cls, f):
        magic = bitcointx.core.serialize.BytesSerializer.stream_deserialize(f)
        message = bitcointx.core.serialize.BytesSerializer.stream_deserialize(f)
        return cls(message, magic)

    def stream_serialize(self, f):
        bitcointx.core.serialize.BytesSerializer.stream_serialize(self.magic, f)
        bitcointx.core.serialize.BytesSerializer.stream_serialize(self.message, f)

    def __str__(self) -> str:
        return self.message.decode('ascii')

    def __repr__(self) -> str:
        return 'BitcoinMessage(%s, %s)' % (self.magic, self.message)
