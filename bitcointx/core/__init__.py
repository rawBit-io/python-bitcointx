# Copyright (C) 2012-2017 The python-bitcoinlib developers
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

# pylama:ignore=E501

import types
import binascii
import struct
from abc import ABCMeta, abstractmethod
from threading import local

from . import script

from .serialize import (
    ImmutableSerializable, MutableSerializableMeta,
    BytesSerializer, VectorSerializer,
    ser_read, uint256_to_str, uint256_from_str,
    Hash, Hash160, make_mutable
)

from .util import (
    no_bool_use_as_property, make_frontend_metaclass, set_frontend_class
)

# Core definitions
COIN = 100000000
MAX_BLOCK_WEIGHT = 4000000
WITNESS_SCALE_FACTOR = 4


_thread_local = local()
_frontend_metaclass = make_frontend_metaclass('_Transaction', _thread_local)


def MoneyRange(nValue, params=None):
    if not params:
        params = _CurrentChainParams()
    return 0 <= nValue <= params.MAX_MONEY


def x(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))


def b2x(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')


def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]


def b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')


def str_money_value(value):
    """Convert an integer money value to a fixed point string"""
    r = '%i.%08i' % (value // COIN, value % COIN)
    r = r.rstrip('0')
    if r[-1] == '.':
        r += '0'
    return r


def str_money_value_for_repr(nValue):
    if nValue >= 0:
        "%s*COIN" % (str_money_value(nValue), )
    else:
        "%d" % (nValue,)


def bytes_for_repr(buf, hexfun=x):
    if hexfun is x:
        bfun = b2x
    elif hexfun is lx:
        bfun = b2lx
    else:
        raise ValueError('invalid hexfun ({}) specified'.format(hexfun))
    if len(buf) > 0 and all(b == buf[0] for b in buf):
        return "{}('{}')*{}".format(hexfun.__name__, bfun(buf[:1]), len(buf))
    return "{}('{}')".format(hexfun.__name__, bfun(buf))


class ValidationError(Exception):
    """Base class for all blockchain validation errors

    Everything that is related to validating the blockchain, blocks,
    transactions, scripts, etc. is derived from this class.
    """


class AddressEncodingError(Exception):
    """Base class for all errors related to address encoding"""


class ReprOrStrMixin(metaclass=ABCMeta):

    @abstractmethod
    def _repr_or_str(self, strfn):
        ...

    def __str__(self):
        return self._repr_or_str(str)

    def __repr__(self):
        return self._repr_or_str(repr)


class _UintBitVectorMeta(type):
    def __init__(self, name, bases, dct):
        if self._UINT_WIDTH_BITS is not None:
            self._UINT_WIDTH_BYTES = self._UINT_WIDTH_BITS // 8
            assert self._UINT_WIDTH_BITS == self._UINT_WIDTH_BYTES * 8
            self.null_instance = bytes([0 for _ in range(self._UINT_WIDTH_BYTES)])


class _UintBitVector(ImmutableSerializable, metaclass=_UintBitVectorMeta):
    # should be specified by subclasses
    _UINT_WIDTH_BITS = None
    # to be set automatically by _UintBitVectorMeta
    _UINT_WIDTH_BYTES = None

    def __init__(self, data=None):
        if data is None:
            data = b'\x00'*self._UINT_WIDTH_BYTES
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('invalid data type, should be bytes')
        if len(data) != self._UINT_WIDTH_BYTES:
            raise ValueError('invalid data length, should be {}'
                             .format(self._UINT_WIDTH_BYTES))
        object.__setattr__(self, 'data', bytes(data))

    @no_bool_use_as_property
    def is_null(self):
        return all(b == 0 for b in self.data)

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f, cls._UINT_WIDTH_BYTES)
        return cls(data)

    def stream_serialize(self, f):
        f.write(self.data)

    def to_hex(self):
        return b2lx(self.data)

    @classmethod
    def from_hex(cls, hexdata):
        return cls(lx(hexdata))

    def __repr__(self):
        return bytes_for_repr(self.data, hexfun=lx)


class Uint256(_UintBitVector):
    _UINT_WIDTH_BITS = 256

    @classmethod
    def from_int(cls, num):
        assert num < 2**256
        return cls(uint256_to_str(num))

    def to_int(self):
        return uint256_from_str(self.data)


class CoinIdentityMeta(type, metaclass=ABCMeta):

    # a dict that holds frontend to concrete class mapping
    _clsmap = None
    # used to ensure set_classmap called only once per coin identity class
    __clsid = None

    def __new__(cls, name, bases, dct):
        new_cls = super(CoinIdentityMeta,
                        cls).__new__(cls, name, bases, dct)

        class AttrAccessHelper:
            def __getattr__(self, name):
                return cls._clsmap[name]

        new_cls._concrete_class = AttrAccessHelper()

        return new_cls

    @classmethod
    def set_classmap(cls, clsmap):
        assert cls._clsmap is None or cls.__clsid != cls, \
            "set_classmap can be called only once for each class"

        cls.__clsid = cls

        required = set((CTransaction, CTxIn, CTxOut, CTxWitness, COutPoint,
                        CTxInWitness, CTxOutWitness, script.CScript))

        supplied = set()
        final_map = {}
        for front, concrete in clsmap.items():
            if front not in required:
                for base in front.__mro__:
                    if base in required:
                        front = base
                        break

            supplied.add(front)
            final_map[front.__name__] = concrete

        missing = required-supplied
        if missing:
            raise ValueError('Required class(es) was not found in clsmap: {}'
                             .format([c.__name__ for c in missing]))
        extra = supplied-required
        if extra:
            raise ValueError('Unexpected class(es) in clsmap: {}'
                             .format([c.__name__ for c in extra]))

        for front, concrete in clsmap.items():
            if type(front) is _frontend_metaclass:
                # regiser the concrete class to frontend class
                # so isinstance and issubclass will work as expected
                front.register(concrete)

            if not issubclass(concrete, front):
                raise ValueError('{} is not a subclass of {}'
                                 .format(concrete.__name__, front.__name__))

        # make the map read-only
        cls._clsmap = types.MappingProxyType(final_map)


class BitcoinIdentityMeta(CoinIdentityMeta):
    ...


class BitcoinMutableIdentityMeta(BitcoinIdentityMeta, MutableSerializableMeta):
    ...


class COutPoint(ImmutableSerializable):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__ = ['hash', 'n']

    def __init__(self, hash=b'\x00'*32, n=0xffffffff):
        if not len(hash) == 32:
            raise ValueError('%s: hash must be exactly 32 bytes; got %d bytes'
                             % self.__class__.__name__, len(hash))
        object.__setattr__(self, 'hash', hash)
        if not (0 <= n <= 0xffffffff):
            raise ValueError('%s: n must be in range 0x0 to 0xffffffff; got %x'
                             % self.__class__.__name__, n)
        object.__setattr__(self, 'n', n)

    @classmethod
    def stream_deserialize(cls, f):
        hash = ser_read(f, 32)
        n = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(hash, n)

    def stream_serialize(self, f):
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b"<I", self.n))

    @no_bool_use_as_property
    def is_null(self):
        return ((self.hash == b'\x00'*32) and (self.n == 0xffffffff))

    def __repr__(self):
        if self.is_null():
            return '%s()' % (
                self.__class__.__name__
            )
        else:
            return '%s(lx(%r), %i)' % (
                self.__class__.__name__,
                b2lx(self.hash), self.n)

    def __str__(self):
        return '%s:%i' % (b2lx(self.hash), self.n)

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create an immutable copy of an existing OutPoint

        If outpoint is already immutable, it is returned directly.
        """
        if not outpoint._immutable_restriction_lifted:
            return outpoint
        else:
            return cls(outpoint.hash, outpoint.n)


@make_mutable
class CMutableOutPoint(COutPoint):
    """A mutable COutPoint"""
    __slots__ = []

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create a mutable copy of an existing COutPoint"""
        return cls(outpoint.hash, outpoint.n)


class CTxInBase(ImmutableSerializable):
    """An input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence']

    def __init__(self, prevout=None, scriptSig=None, nSequence=0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        if prevout is None:
            prevout = self._concrete_class.COutPoint()
        elif self._immutable_restriction_lifted != prevout._immutable_restriction_lifted:
            prevout = self._concrete_class.COutPoint.from_outpoint(prevout)
        object.__setattr__(self, 'nSequence', nSequence)
        object.__setattr__(self, 'prevout', prevout)
        object.__setattr__(self, 'scriptSig', scriptSig)

    @classmethod
    def stream_deserialize(cls, f):
        prevout = cls._concrete_class.COutPoint.stream_deserialize(f)
        scriptSig = BytesSerializer.stream_deserialize(f)
        nSequence = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(prevout, scriptSig, nSequence)

    def stream_serialize(self, f):
        self._concrete_class.COutPoint.stream_serialize(self.prevout, f)
        BytesSerializer.stream_serialize(self.scriptSig, f)
        f.write(struct.pack(b"<I", self.nSequence))

    @no_bool_use_as_property
    def is_final(self):
        return (self.nSequence == 0xffffffff)


class CBitcoinTxIn(CTxInBase, metaclass=BitcoinIdentityMeta):

    def __init__(self, prevout=None, scriptSig=script.CBitcoinScript(),
                 nSequence=0xffffffff):
        if not isinstance(scriptSig, script.CBitcoinScript):
            assert isinstance(scriptSig, (bytes, bytearray))
            scriptSig = script.CBitcoinScript(scriptSig)
        super(CBitcoinTxIn, self).__init__(prevout, scriptSig, nSequence)

    @classmethod
    def from_txin(cls, txin):
        """Create an immutable copy of an existing TxIn

        If txin is already immutable, it is returned directly.
        """
        if not isinstance(txin, CBitcoinTxIn):
            raise ValueError(
                'incompatible txin class: expected instance of {}, got {}'
                .format(CBitcoinTxIn.__name__, txin.__class__.__name__))
        if not txin._immutable_restriction_lifted:
            # txin is immutable, therefore returning same txin is OK
            return txin
        else:
            return cls(
                cls._concrete_class.COutPoint.from_outpoint(txin.prevout),
                txin.scriptSig, txin.nSequence)

    def __repr__(self):
        return "C%sTxIn(%s, %s, 0x%x)" % (
            'Mutable' if self._immutable_restriction_lifted else '',
            repr(self.prevout), repr(self.scriptSig), self.nSequence)


class CBitcoinMutableTxIn(CBitcoinTxIn, metaclass=BitcoinMutableIdentityMeta):
    """A mutable CTxIn"""
    __slots__ = []

    @classmethod
    def from_txin(cls, txin):
        """Create a fully mutable copy of an existing TxIn"""
        if not isinstance(txin, CBitcoinTxIn):
            raise ValueError(
                'incompatible txin class: expected instance of {}, got {}'
                .format(CBitcoinTxIn.__name__, txin.__class__.__name__))
        prevout = cls._concrete_class.COutPoint.from_outpoint(txin.prevout)
        return cls(prevout, txin.scriptSig, txin.nSequence)


class CBitcoinTxOutCommon(ImmutableSerializable):
    """An output of a transaction

    Contains the public key that the next input must be able to sign with to
    claim it.
    """
    __slots__ = ['nValue', 'scriptPubKey']

    def __init__(self, nValue=-1, scriptPubKey=script.CBitcoinScript()):
        if not isinstance(scriptPubKey, script.CBitcoinScript):
            assert isinstance(scriptPubKey, (bytes, bytearray))
            scriptPubKey = script.CBitcoinScript(scriptPubKey)
        object.__setattr__(self, 'nValue', int(nValue))
        object.__setattr__(self, 'scriptPubKey', scriptPubKey)

    @classmethod
    def stream_deserialize(cls, f):
        nValue = struct.unpack(b"<q", ser_read(f, 8))[0]
        scriptPubKey = BytesSerializer.stream_deserialize(f)
        return cls(nValue, scriptPubKey)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<q", self.nValue))
        BytesSerializer.stream_serialize(self.scriptPubKey, f)

    @no_bool_use_as_property
    def is_valid(self):
        if not MoneyRange(self.nValue):
            return False
        if not self.scriptPubKey.is_valid():
            return False
        return True

    def __repr__(self):
        return "%s(%s, %r)" % (
            self.__class__.__name__,
            str_money_value_for_repr(self.nValue), self.scriptPubKey)


class CBitcoinTxOut(CBitcoinTxOutCommon):

    @classmethod
    def from_txout(cls, txout):
        """Create an immutable copy of an existing TxOut

        If txout is already immutable, then it will be returned directly.
        """
        if not isinstance(txout, CBitcoinTxOut):
            raise ValueError(
                'incompatible txout class: expected instance of {}, got {}'
                .format(CBitcoinTxOut.__name__, txout.__class__.__name__))
        if not txout._immutable_restriction_lifted:
            return txout
        else:
            return cls(txout.nValue, txout.scriptPubKey)


@make_mutable
class CBitcoinMutableTxOut(CBitcoinTxOut):
    """A mutable CTxOut"""
    __slots__ = []

    @classmethod
    def from_txout(cls, txout):
        """Create a fullly mutable copy of an existing TxOut"""
        if not isinstance(txout, CBitcoinTxOut):
            raise ValueError(
                'incompatible txout class: expected instance of {}, got {}'
                .format(CBitcoinTxOut.__name__, txout.__class__.__name__))
        return cls(txout.nValue, txout.scriptPubKey)


class CBitcoinTxInWitness(ImmutableSerializable):
    """Witness data for a single transaction input"""
    __slots__ = ['scriptWitness']

    def __init__(self, scriptWitness=script.CScriptWitness()):
        object.__setattr__(self, 'scriptWitness', scriptWitness)

    @no_bool_use_as_property
    def is_null(self):
        return self.scriptWitness.is_null()

    @classmethod
    def stream_deserialize(cls, f):
        scriptWitness = script.CScriptWitness.stream_deserialize(f)
        return cls(scriptWitness)

    def stream_serialize(self, f):
        self.scriptWitness.stream_serialize(f)

    @classmethod
    def from_txin_witness(cls, txin_witness):
        if not isinstance(txin_witness, CBitcoinTxInWitness):
            raise ValueError(
                'incompatible txin witness class: expected instance of {}, got {}'
                .format(CBitcoinTxInWitness.__name__,
                        txin_witness.__class__.__name__))
        if not txin_witness._immutable_restriction_lifted:
            # txin_witness is immutable, therefore returning same txin_witness is OK
            return txin_witness
        return cls(txin_witness.scriptWitness)

    def __repr__(self):
        return "C%sTxInWitness(%s)" % (
            'Mutable' if self._immutable_restriction_lifted else '',
            repr(self.scriptWitness))


@make_mutable
class CBitcoinMutableTxInWitness(CBitcoinTxInWitness):

    @classmethod
    def from_txin_witness(cls, txin_witness):
        """Create a mutable copy of an existing TxInWitness"""
        if not isinstance(txin_witness, CBitcoinTxInWitness):
            raise ValueError(
                'incompatible txin witness class: expected instance of {}, got {}'
                .format(CBitcoinTxInWitness.__name__,
                        txin_witness.__class__.__name__))
        return cls(txin_witness.scriptWitness)


class CTxOutWitnessBase(ImmutableSerializable):
    pass


class _CBitcoinDummyTxOutWitness(CTxOutWitnessBase):
    pass


class CTxWitnessBase(ImmutableSerializable):
    pass


class CBitcoinTxWitness(CTxWitnessBase):
    """Witness data for all inputs to a transaction"""
    __slots__ = ['vtxinwit']
    _txin_witness_class = CBitcoinTxInWitness
    _txout_witness_class = _CBitcoinDummyTxOutWitness

    def __init__(self, vtxinwit=()):
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        object.__setattr__(self, 'vtxinwit',
                           tuple(w if not w._immutable_restriction_lifted
                                 else self._txin_witness_class.from_txin_witness(w)
                                 for w in vtxinwit))

    @no_bool_use_as_property
    def is_null(self):
        for n in range(len(self.vtxinwit)):
            if not self.vtxinwit[n].is_null():
                return False
        return True

    # NOTE: this cannot be a @classmethod like the others because we need to
    # know how many items to deserialize, which comes from len(vin)
    def stream_deserialize(self, f):
        vtxinwit = tuple(self._txin_witness_class.stream_deserialize(f)
                         for dummy in range(len(self.vtxinwit)))
        return self.__class__(vtxinwit)

    def stream_serialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].stream_serialize(f)

    @classmethod
    def from_witness(cls, witness):
        if not isinstance(witness, CBitcoinTxWitness):
            raise ValueError(
                'incompatible tx witness class: expected instance of{}, got {}'
                .format(CBitcoinTxWitness.__name__, witness.__class__.__name__))
        if not witness._immutable_restriction_lifted:
            return witness
        vtxinwit = (cls._txin_witness_class.from_txin_witness(txinwit)
                    for txinwit in witness.vtxinwit)
        return cls(vtxinwit)

    def __repr__(self):
        return "C%sTxWitness([%s])" % (
            'Mutable' if self._immutable_restriction_lifted else '',
            ','.join(repr(w) for w in self.vtxinwit))


@make_mutable
class CBitcoinMutableTxWitness(CBitcoinTxWitness):
    """Witness data for all inputs to a transaction, mutable version"""
    __slots__ = []
    _txin_witness_class = CBitcoinMutableTxInWitness

    def __init__(self, vtxinwit=(), vtxoutwit=None):
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        self.vtxinwit = [w if w._immutable_restriction_lifted
                         else self.__class__._txin_witness_class.from_txin_witness(w)
                         for w in vtxinwit]

    @classmethod
    def from_witness(cls, witness):
        if not isinstance(witness, CBitcoinTxWitness):
            raise ValueError(
                'incompatible tx witness class: expected instance of {}, got {}'
                .format(CBitcoinTxWitness.__name__, witness.__class__.__name__))
        vtxinwit = (cls._txin_witness_class.from_txin_witness(txinwit)
                    for txinwit in witness.vtxinwit)
        return cls(vtxinwit)


class CTransactionBase(ImmutableSerializable, ReprOrStrMixin):
    """A transaction"""
    __slots__ = ['nVersion', 'vin', 'vout', 'nLockTime', 'wit']

    _witness_class = None
    _txin_class = None
    _txout_class = None

    CURRENT_VERSION = 2

    def __init__(self, vin=(), vout=(), nLockTime=0, nVersion=None, witness=None):
        """Create a new transaction

        vin and vout are iterables of transaction inputs and outputs
        respectively. If their contents are not already immutable, immutable
        copies will be made.
        """
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)

        if witness is None:
            witness = self._witness_class()

        if nVersion is None:
            nVersion = self.CURRENT_VERSION

        object.__setattr__(self, 'nLockTime', nLockTime)
        object.__setattr__(self, 'nVersion', nVersion)
        object.__setattr__(self, 'vin', tuple(self._txin_class.from_txin(txin) for txin in vin))
        object.__setattr__(self, 'vout', tuple(self._txout_class.from_txout(txout) for txout in vout))
        object.__setattr__(self, 'wit', self._witness_class.from_witness(witness))

    @no_bool_use_as_property
    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def has_witness(self):
        """True if witness"""
        return not self.wit.is_null()

    def _repr_or_str(self, strfn):
        return "C%sTransaction(%s, %s, %i, %i, %s)" % (
            'Mutable' if self._immutable_restriction_lifted else '',
            ', '.join(strfn(v) for v in self.vin), ', '.join(strfn(v) for v in self.vout),
            self.nLockTime, self.nVersion, strfn(self.wit))

    def GetTxid(self):
        """Get the transaction ID.  This differs from the transactions hash as
            given by GetHash.  GetTxid excludes witness data, while GetHash
            includes it. """

        if not self.wit.is_null():
            txid = Hash(CTransaction(self.vin, self.vout, self.nLockTime,
                                     self.nVersion).serialize())
        else:
            txid = Hash(self.serialize())
        return txid

    def to_mutable(self):
        if self._immutable_restriction_lifted:
            return self.__class__.from_tx(self)
        return self._inverted_mutability_class.from_tx(self)

    def to_immutable(self):
        if not self._immutable_restriction_lifted:
            return self.__class__.from_tx(self)
        return self._inverted_mutability_class.from_tx(self)

    @classmethod
    def _from_tx(cls, tx):
        vin = [cls._txin_class.from_txin(txin) for txin in tx.vin]
        vout = [cls._txout_class.from_txout(txout) for txout in tx.vout]
        wit = cls._witness_class.from_witness(tx.wit)
        return cls(vin, vout, tx.nLockTime, tx.nVersion, wit)


class CImmutableTransactionBase(CTransactionBase):
    @classmethod
    def from_tx(cls, tx):
        """Create an immutable copy of a pre-existing transaction

        If tx is already immutable, then it will be returned directly.
        """
        if not tx._immutable_restriction_lifted:
            # tx is immutable, therefore returning same tx is OK
            return tx

        return cls._from_tx(tx)


@make_mutable
class CMutableTransactionBase(CTransactionBase):
    """A mutable transaction"""
    __slots__ = []

    def __init__(self, vin=None, vout=None, nLockTime=0, nVersion=None, witness=None):
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)

        if nVersion is None:
            nVersion = self.CURRENT_VERSION

        self.nLockTime = nLockTime

        if vin is None:
            self.vin = []
        else:
            self.vin = [inp if inp._immutable_restriction_lifted
                        else self.__class__._txin_class.from_txin(inp)
                        for inp in vin]

        if vout is None:
            self.vout = []
        else:
            self.vout = [out if out._immutable_restriction_lifted
                         else self.__class__._txout_class.from_txout(out)
                         for out in vout]
        self.nVersion = nVersion

        wclass = self._witness_class
        if witness is None or witness.is_null():
            self.wit = wclass([wclass._txin_witness_class() for dummy in range(len(self.vin))],
                              [wclass._txout_witness_class() for dummy in range(len(self.vout))])

        elif not witness._immutable_restriction_lifted:
            self.wit = wclass.from_witness(witness)
        else:
            self.wit = witness

    @classmethod
    def from_tx(cls, tx):
        """Create a fully mutable copy of a pre-existing transaction"""
        # tx is mutable, we should always return new instance
        return cls._from_tx(tx)


class CBitcoinTransactionCommon():

    @classmethod
    def stream_deserialize(cls, f):
        """Deserialize transaction

        This implementation corresponds to Bitcoin's SerializeTransaction() and
        consensus behavior. Note that Bitcoin's DecodeHexTx() also has the
        option to attempt deserializing as a non-witness transaction first,
        falling back to the consensus behavior if it fails. The difference lies
        in transactions which have zero inputs: they are invalid but may be
        (de)serialized anyway for the purpose of signing them and adding
        inputs. If the behavior of DecodeHexTx() is needed it could be added,
        but not here.
        """
        # FIXME can't assume f is seekable
        nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
        pos = f.tell()
        markerbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        flagbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        if markerbyte == 0 and flagbyte == 1:
            vin = VectorSerializer.stream_deserialize(cls._txin_class, f)
            vout = VectorSerializer.stream_deserialize(cls._txout_class, f)
            wit = cls._witness_class(tuple(cls._witness_class._txin_witness_class()
                                           for dummy in range(len(vin))))
            wit = wit.stream_deserialize(f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion, wit)
        else:
            f.seek(pos)  # put marker byte back, since we don't have peek
            vin = VectorSerializer.stream_deserialize(cls._txin_class, f)
            vout = VectorSerializer.stream_deserialize(cls._txout_class, f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion)

    def stream_serialize(self, f, include_witness=True, for_sighash=False):
        f.write(struct.pack(b"<i", self.nVersion))
        if include_witness and not self.wit.is_null():
            assert(len(self.wit.vtxinwit) == len(self.vin))
            f.write(b'\x00')  # Marker
            f.write(b'\x01')  # Flag
            VectorSerializer.stream_serialize(self._txin_class, self.vin, f)
            VectorSerializer.stream_serialize(self._txout_class, self.vout, f)
            self.wit.stream_serialize(f)
        else:
            VectorSerializer.stream_serialize(self._txin_class, self.vin, f)
            VectorSerializer.stream_serialize(self._txout_class, self.vout, f)
        f.write(struct.pack(b"<I", self.nLockTime))

    @classmethod
    def from_tx(cls, tx):
        if not isinstance(tx, CBitcoinTransactionCommon):
            raise ValueError(
                'incompatible tx class: expected instance of {}, got {}'
                .format(CBitcoinTransactionCommon.__name__,
                        tx.__class__.__name__))
        return super(CBitcoinTransactionCommon, cls).from_tx(tx)


class CBitcoinMutableTransaction(CBitcoinTransactionCommon, CMutableTransactionBase):
    # _inverted_mutability_class will be set in _SetTransactionClassParams
    _witness_class = CBitcoinMutableTxWitness
    _txin_class = CBitcoinMutableTxIn
    _txout_class = CBitcoinMutableTxOut


class CBitcoinTransaction(CBitcoinTransactionCommon, CImmutableTransactionBase):
    _inverted_mutability_class = CBitcoinMutableTransaction
    _witness_class = CBitcoinTxWitness
    _txin_class = CBitcoinTxIn
    _txout_class = CBitcoinTxOut


class CheckTransactionError(ValidationError):
    pass


def CheckTransaction(tx):  # noqa
    """Basic transaction checks that don't depend on any context.

    Raises CheckTransactionError
    """

    if not tx.vin:
        raise CheckTransactionError("CheckTransaction() : vin empty")
    if not tx.vout:
        raise CheckTransactionError("CheckTransaction() : vout empty")

    # Size limits
    base_tx = tx.to_immutable()
    if len(base_tx.serialize({'include_witness': False})) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        raise CheckTransactionError("CheckTransaction() : size limits failed")

    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.vout:
        if txout.nValue < 0:
            raise CheckTransactionError("CheckTransaction() : txout.nValue negative")
        if txout.nValue > _CurrentChainParams().MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : txout.nValue too high")
        nValueOut += txout.nValue
        if not MoneyRange(nValueOut):
            raise CheckTransactionError("CheckTransaction() : txout total out of range")

    # Check for duplicate inputs
    vin_outpoints = set()
    for txin in tx.vin:
        if txin.prevout in vin_outpoints:
            raise CheckTransactionError("CheckTransaction() : duplicate inputs")
        vin_outpoints.add(txin.prevout)

    if tx.is_coinbase():
        if not (2 <= len(tx.vin[0].scriptSig) <= 100):
            raise CheckTransactionError("CheckTransaction() : coinbase script size")

    else:
        for txin in tx.vin:
            if txin.prevout.is_null():
                raise CheckTransactionError("CheckTransaction() : prevout is null")


def GetLegacySigOpCount(tx):
    nSigOps = 0
    for txin in tx.vin:
        nSigOps += txin.scriptSig.GetSigOpCount(False)
    for txout in tx.vout:
        nSigOps += txout.scriptPubKey.GetSigOpCount(False)
    return nSigOps


class CTransaction(metaclass=_frontend_metaclass):
    pass


class CMutableTransaction(CTransaction):
    pass


class CTxWitness(metaclass=_frontend_metaclass):
    pass


class CMutableTxWitness(CTxWitness):
    pass


class CTxInWitness(metaclass=_frontend_metaclass):
    pass


class CMutableTxInWitness(CTxInWitness):
    pass


class CTxOutWitness(metaclass=_frontend_metaclass):
    pass


class CMutableTxOutWitness(CTxOutWitness):
    pass


class CTxIn(metaclass=_frontend_metaclass):
    pass


class CMutableTxIn(CTxIn):
    pass


class CTxOut(metaclass=_frontend_metaclass):
    pass


class CMutableTxOut(CTxOut):
    pass


BitcoinIdentityMeta.set_classmap({
    CTransaction: CBitcoinTransaction,
    CTxIn: CBitcoinTxIn,
    CTxOut: CBitcoinTxOut,
    CTxWitness: CBitcoinTxWitness,
    CTxInWitness: CBitcoinTxInWitness,
    CTxOutWitness: _CBitcoinDummyTxOutWitness,
    COutPoint: COutPoint,
    script.CScript: script.CBitcoinScript
})

BitcoinMutableIdentityMeta.set_classmap({
    CMutableTransaction: CBitcoinMutableTransaction,
    CMutableTxIn: CBitcoinMutableTxIn,
    CMutableTxOut: CBitcoinMutableTxOut,
    CMutableTxWitness: CBitcoinMutableTxWitness,
    CMutableTxInWitness: CBitcoinMutableTxInWitness,
    CMutableTxOutWitness: _CBitcoinDummyTxOutWitness,
    CMutableOutPoint: CMutableOutPoint,
    script.CScript: script.CBitcoinScript
})


def _SetTransactionClassParams(transaction_class):
    imm_class = transaction_class
    mut_class = transaction_class._inverted_mutability_class
    mut_class._inverted_mutability_class = imm_class

    def sfc(frontend_cls, concrete_cls):
        set_frontend_class(frontend_cls, concrete_cls, _thread_local)

    sfc(CTransaction, imm_class)
    sfc(CTxIn, imm_class._txin_class)
    sfc(CTxOut, imm_class._txout_class)
    sfc(CTxWitness, imm_class._witness_class)
    sfc(CTxInWitness, imm_class._witness_class._txin_witness_class)
    sfc(CTxOutWitness, imm_class._witness_class._txout_witness_class)

    sfc(CMutableTransaction, mut_class)
    sfc(CMutableTxIn, mut_class._txin_class)
    sfc(CMutableTxOut, mut_class._txout_class)
    sfc(CMutableTxWitness, mut_class._witness_class)
    sfc(CMutableTxInWitness, mut_class._witness_class._txin_witness_class)
    sfc(CMutableTxOutWitness, mut_class._witness_class._txout_witness_class)


def _SetChainParams(params):
    _thread_local.chain_params = params
    _SetTransactionClassParams(params.TRANSACTION_CLASS)


def _CurrentChainParams():
    return _thread_local.chain_params


_SetTransactionClassParams(CBitcoinTransaction)

__all__ = (
    'Hash',
    'Hash160',
    'COIN',
    'MoneyRange',
    'x',
    'b2x',
    'lx',
    'b2lx',
    'str_money_value',
    'ValidationError',
    'AddressEncodingError',
    'COutPoint',
    'CMutableOutPoint',
    'CTxIn',
    'CMutableTxIn',
    'CTxOut',
    'CMutableTxOut',
    'CTransaction',
    'CMutableTransaction',
    'CTxWitness',
    'CMutableTxWitness',
    'CMutableTxInWitness',
    'CMutableTxOutWitness',
    'CTxInWitness',
    'CTxOutWitness',
    'CheckTransactionError',
    'CheckTransaction',
    'GetLegacySigOpCount',
    'Uint256',
    'bytes_for_repr',
    'str_money_value_for_repr',
)
