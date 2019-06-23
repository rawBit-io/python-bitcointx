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

import binascii
import struct
from abc import ABCMeta, abstractmethod
from threading import local

from . import script

from .serialize import (
    ImmutableSerializable, MutableSerializableMeta,
    BytesSerializer, VectorSerializer,
    ser_read, uint256_to_str, uint256_from_str,
    Hash, Hash160
)

from .util import (
    no_bool_use_as_property, make_frontend_metaclass, set_frontend_class,
    CoinIdentityMeta
)

# Core definitions
COIN = 100000000
MAX_BLOCK_WEIGHT = 4000000
WITNESS_SCALE_FACTOR = 4


_thread_local = local()
_frontend_metaclass = make_frontend_metaclass('_Transaction', _thread_local)


def MoneyRange(nValue, params=None):
    if not params:
        params = _GetCurrentChainParams()
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


class ReprOrStrMixin():

    @abstractmethod
    def _repr_or_str(self, strfn):
        ...

    def __str__(self):
        return self._repr_or_str(str)

    def __repr__(self):
        return self._repr_or_str(repr)


def _check_inst_compatible(inst, imm_concrete_class):
    if not isinstance(inst, imm_concrete_class):
        raise ValueError(
            'incompatible class: expected instance of {}, got {}'
            .format(imm_concrete_class.__name__, inst.__class__.__name__))


def _is_mut_cls(cls):
    # The base class is always ImmutableSerializable
    assert issubclass(cls, ImmutableSerializable)

    # But MutableSerializableMeta might be added that will make it mutable
    return issubclass(type(cls), MutableSerializableMeta)


def _is_mut_inst(inst):
    # The base class is always ImmutableSerializable
    assert isinstance(inst, ImmutableSerializable)

    # But MutableSerializableMeta might be added that will make it mutable
    return issubclass(type(type(inst)), MutableSerializableMeta)


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


class CoinTransactionIdentityMeta(CoinIdentityMeta, metaclass=ABCMeta):

    _frontend_metaclass = _frontend_metaclass

    @classmethod
    def _get_required_classes(cls):
        """Return two sets of frontend classes: one that is expected
        to be set via set_classmap() and is the classes that is actually
        implemented in this module, and another set is frontend classes
        that are merely used bu the first set of classes, and that must
        be in the mapping returned by _get_extra_classmap()"""
        return (set((CTransaction, CTxIn, CTxOut, CTxWitness, COutPoint,
                    CTxInWitness, CTxOutWitness)),
                set([script.CScript]))

    @classmethod
    def set_mutable_immutable_links(cls, other_identity):
        is_mut = issubclass(cls, MutableSerializableMeta)
        if is_mut:
            mut_identity = cls
            imm_identity = other_identity
        else:
            mut_identity = other_identity
            imm_identity = cls

        mut_access = mut_identity._get_attr_access_helper()
        imm_access = imm_identity._get_attr_access_helper()

        assert 'immutable' not in mut_identity._namemap,\
            ("set_mutable_immutable_links must be called only once, "
             "either on mutable or on immutable identity, not both")

        mut_identity._namemap['mutable'] = mut_access
        mut_identity._namemap['immutable'] = imm_access

        imm_identity._namemap['mutable'] = mut_access
        imm_identity._namemap['immutable'] = imm_access

        mut_identity._immutable_identity = imm_identity
        imm_identity._mutable_identity = mut_identity


class BitcoinTransactionIdentityMeta(CoinTransactionIdentityMeta):
    @classmethod
    def _get_extra_classmap(cls):
        return {script.CScript: script.CBitcoinScript}


class BitcoinMutableTransactionIdentityMeta(BitcoinTransactionIdentityMeta,
                                            MutableSerializableMeta):
    ...


class COutPointBase(ImmutableSerializable):
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
        """Create a mutable or immutable copy of an existing OutPoint,
        depending on the class this method is called on.

        If cls and outpoint are both immutable, outpoint is returned directly.
        """
        _check_inst_compatible(outpoint,
                               cls._concrete_class.immutable.COutPoint)

        if not _is_mut_cls(cls) and not _is_mut_inst(outpoint):
            return outpoint

        return cls(outpoint.hash, outpoint.n)


class CBitcoinOutPoint(COutPointBase,
                       metaclass=BitcoinTransactionIdentityMeta):
    """Bitcoin COutPoint"""
    __slots__ = []


class CBitcoinMutableOutPoint(CBitcoinOutPoint,
                              metaclass=BitcoinMutableTransactionIdentityMeta):
    """A mutable Bitcoin COutPoint"""
    __slots__ = []


class CTxInBase(ImmutableSerializable):
    """A base class for an input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence']

    def __init__(self, prevout=None, scriptSig=None, nSequence=0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        if scriptSig is None:
            scriptSig = self._concrete_class.CScript()
        elif not isinstance(scriptSig, self._concrete_class.CScript):
            assert isinstance(scriptSig, (bytes, bytearray)), scriptSig.__class__
            scriptSig = self._concrete_class.CScript(scriptSig)
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

    @classmethod
    def from_txin(cls, txin):
        """Create a mutable or immutable copy of an existing TxIn,
        depending on the class this method is called on.

        If cls and txin are both immutable, txin is returned directly.
        """

        _check_inst_compatible(txin, cls._concrete_class.immutable.CTxIn)

        if not _is_mut_cls(cls) and not _is_mut_inst(txin):
            return txin

        return cls(
            cls._concrete_class.COutPoint.from_outpoint(txin.prevout),
            txin.scriptSig, txin.nSequence)

    def __repr__(self):
        return "%s(%s, %s, 0x%x)" % (
            self.__class__.__name__,
            repr(self.prevout), repr(self.scriptSig), self.nSequence)


class CBitcoinTxIn(CTxInBase, metaclass=BitcoinTransactionIdentityMeta):
    """An immutable Bitcoin TxIn"""
    __slots__ = []


class CBitcoinMutableTxIn(CBitcoinTxIn,
                          metaclass=BitcoinMutableTransactionIdentityMeta):
    """A mutable Bitcoin TxIn"""
    __slots__ = []


class CTxOutBase(ImmutableSerializable):
    """A base class for an output of a transaction

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

    @classmethod
    def from_txout(cls, txout):
        """Create a mutable or immutable copy of an existing TxOut,
        depending on the class this method is called on.

        If cls and txout are both immutable, txout is returned directly.
        """

        _check_inst_compatible(txout, cls._concrete_class.immutable.CTxOut)

        if not _is_mut_cls(cls) and not _is_mut_inst(txout):
            return txout

        return cls(txout.nValue, txout.scriptPubKey)


class CBitcoinTxOut(CTxOutBase, metaclass=BitcoinTransactionIdentityMeta):
    """A immutable Bitcoin TxOut"""
    __slots__ = []


class CBitcoinMutableTxOut(CBitcoinTxOut,
                           metaclass=BitcoinMutableTransactionIdentityMeta):
    """A mutable Bitcoin CTxOut"""
    __slots__ = []


class CTxInWitnessBase(ImmutableSerializable):
    """A base class for witness data for a single transaction input"""
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
        _check_inst_compatible(txin_witness,
                               cls._concrete_class.immutable.CTxInWitness)

        if not _is_mut_cls(cls) and not _is_mut_inst(txin_witness):
            return txin_witness

        return cls(txin_witness.scriptWitness)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.scriptWitness))


class CBitcoinTxInWitness(CTxInWitnessBase,
                          metaclass=BitcoinTransactionIdentityMeta):
    """Immutable Bitcoin witness data for a single transaction input"""
    __slots__ = []


class CBitcoinMutableTxInWitness(CBitcoinTxInWitness,
                                 metaclass=BitcoinMutableTransactionIdentityMeta):
    """Mutable Bitcoin witness data for a single transaction input"""
    __slots__ = []


class CTxOutWitnessBase(ImmutableSerializable):
    pass


class _CBitcoinDummyTxOutWitness(CTxOutWitnessBase):
    pass


class CTxWitnessBase(ImmutableSerializable):
    """Witness data for all inputs to a transaction"""
    __slots__ = ['vtxinwit']

    def __init__(self, vtxinwit=(), vtxoutwit=None):
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        txinwit = []
        for w in vtxinwit:
            _check_inst_compatible(
                w, self._concrete_class.immutable.CTxInWitness)
            if _is_mut_inst(self) or _is_mut_inst(w):
                txinwit.append(self._concrete_class.CTxInWitness.from_txin_witness(w))
            else:
                txinwit.append(w)

        if not _is_mut_inst(self):
            txinwit = tuple(txinwit)

        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        object.__setattr__(self, 'vtxinwit', txinwit)

    @no_bool_use_as_property
    def is_null(self):
        for n in range(len(self.vtxinwit)):
            if not self.vtxinwit[n].is_null():
                return False
        return True

    # NOTE: this cannot be a @classmethod like the others because we need to
    # know how many items to deserialize, which comes from len(vin)
    def stream_deserialize(self, f):
        vtxinwit = tuple(self._concrete_class.CTxInWitness.stream_deserialize(f)
                         for dummy in range(len(self.vtxinwit)))
        return self.__class__(vtxinwit)

    def stream_serialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].stream_serialize(f)

    @classmethod
    def from_witness(cls, witness):
        _check_inst_compatible(witness,
                               cls._concrete_class.immutable.CTxWitness)

        if not _is_mut_cls(cls) and not _is_mut_inst(witness):
            return witness

        vtxinwit = (cls._concrete_class.CTxInWitness.from_txin_witness(w)
                    for w in witness.vtxinwit)

        return cls(vtxinwit)

    def __repr__(self):
        return "%s([%s])" % (self.__class__.__name__,
                             ','.join(repr(w) for w in self.vtxinwit))


class CBitcoinTxWitness(CTxWitnessBase,
                        metaclass=BitcoinTransactionIdentityMeta):
    """Immutable witness data for all inputs to a transaction"""
    __slots__ = []


class CBitcoinMutableTxWitness(CBitcoinTxWitness,
                               metaclass=BitcoinMutableTransactionIdentityMeta):
    """Witness data for all inputs to a transaction, mutable version"""
    __slots__ = []


class CTransactionBase(ImmutableSerializable, ReprOrStrMixin):
    __slots__ = ['nVersion', 'vin', 'vout', 'nLockTime', 'wit']

    CURRENT_VERSION = 2

    def __init__(self, vin=(), vout=(), nLockTime=0, nVersion=None, witness=None):
        """Create a new transaction

        vin and vout are iterables of transaction inputs and outputs
        respectively. If their contents are not already immutable, immutable
        copies will be made.
        """
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)

        if nVersion is None:
            nVersion = self.CURRENT_VERSION

        wclass = self._concrete_class.CTxWitness
        txin_wclass = self._concrete_class.CTxInWitness
        txout_wclass = self._concrete_class.CTxOutWitness

        if witness is None or witness.is_null():
            if witness is None and not _is_mut_inst(self):
                witness = wclass()
            else:
                witness = wclass(
                    [txin_wclass() for dummy in range(len(vin))],
                    [txout_wclass() for dummy in range(len(vout))])
        else:
            witness = wclass.from_witness(witness)

        tuple_or_list = list if _is_mut_inst(self) else tuple

        object.__setattr__(self, 'nLockTime', nLockTime)
        object.__setattr__(self, 'nVersion', nVersion)
        object.__setattr__(self, 'vin', tuple_or_list(
            self._concrete_class.CTxIn.from_txin(txin) for txin in vin))
        object.__setattr__(self, 'vout', tuple_or_list(
            self._concrete_class.CTxOut.from_txout(txout) for txout in vout))
        object.__setattr__(self, 'wit', witness)

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
        return self._concrete_class.mutable.CTransaction.from_tx(self)

    def to_immutable(self):
        return self._concrete_class.immutable.CTransaction.from_tx(self)

    @classmethod
    def from_tx(cls, tx):
        _check_inst_compatible(tx,
                               cls._concrete_class.immutable.CTransaction)

        if not _is_mut_cls(cls) and not _is_mut_inst(tx):
            return tx

        vin = [cls._concrete_class.CTxIn.from_txin(txin) for txin in tx.vin]
        vout = [cls._concrete_class.CTxOut.from_txout(txout)
                for txout in tx.vout]
        wit = cls._concrete_class.CTxWitness.from_witness(tx.wit)
        return cls(vin, vout, tx.nLockTime, tx.nVersion, wit)

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
            vin = VectorSerializer.stream_deserialize(
                cls._concrete_class.CTxIn, f)
            vout = VectorSerializer.stream_deserialize(
                cls._concrete_class.CTxOut, f)
            wit = cls._concrete_class.CTxWitness(
                tuple(cls._concrete_class.CTxInWitness()
                      for dummy in range(len(vin))))
            wit = wit.stream_deserialize(f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion, wit)
        else:
            f.seek(pos)  # put marker byte back, since we don't have peek
            vin = VectorSerializer.stream_deserialize(
                cls._concrete_class.CTxIn, f)
            vout = VectorSerializer.stream_deserialize(
                cls._concrete_class.CTxOut, f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion)

    def stream_serialize(self, f, include_witness=True, for_sighash=False):
        f.write(struct.pack(b"<i", self.nVersion))
        if include_witness and not self.wit.is_null():
            assert(len(self.wit.vtxinwit) == len(self.vin))
            f.write(b'\x00')  # Marker
            f.write(b'\x01')  # Flag
            VectorSerializer.stream_serialize(
                self._concrete_class.CTxIn, self.vin, f)
            VectorSerializer.stream_serialize(
                self._concrete_class.CTxOut, self.vout, f)
            self.wit.stream_serialize(f)
        else:
            VectorSerializer.stream_serialize(
                self._concrete_class.CTxIn, self.vin, f)
            VectorSerializer.stream_serialize(
                self._concrete_class.CTxOut, self.vout, f)
        f.write(struct.pack(b"<I", self.nLockTime))


class CBitcoinMutableTransaction(CTransactionBase,
                                 metaclass=BitcoinMutableTransactionIdentityMeta):
    """Bitcoin transaction"""
    __slots__ = []


class CBitcoinTransaction(CTransactionBase,
                          metaclass=BitcoinTransactionIdentityMeta):
    """Bitcoin transaction, mutable version"""
    __slots__ = []


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
        if txout.nValue > _GetCurrentChainParams().MAX_MONEY:
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


class COutPoint(metaclass=_frontend_metaclass):
    pass


class CMutableOutPoint(COutPoint):
    pass


class CTxIn(metaclass=_frontend_metaclass):
    pass


class CMutableTxIn(CTxIn):
    pass


class CTxOut(metaclass=_frontend_metaclass):
    pass


class CMutableTxOut(CTxOut):
    pass


BitcoinTransactionIdentityMeta.set_classmap({
    CTransaction: CBitcoinTransaction,
    CTxIn: CBitcoinTxIn,
    CTxOut: CBitcoinTxOut,
    CTxWitness: CBitcoinTxWitness,
    CTxInWitness: CBitcoinTxInWitness,
    CTxOutWitness: _CBitcoinDummyTxOutWitness,
    COutPoint: CBitcoinOutPoint,
})

BitcoinMutableTransactionIdentityMeta.set_classmap({
    CMutableTransaction: CBitcoinMutableTransaction,
    CMutableTxIn: CBitcoinMutableTxIn,
    CMutableTxOut: CBitcoinMutableTxOut,
    CMutableTxWitness: CBitcoinMutableTxWitness,
    CMutableTxInWitness: CBitcoinMutableTxInWitness,
    CMutableTxOutWitness: _CBitcoinDummyTxOutWitness,
    CMutableOutPoint: CBitcoinMutableOutPoint,
})

BitcoinMutableTransactionIdentityMeta.set_mutable_immutable_links(
    BitcoinTransactionIdentityMeta)


def _SetTransactionCoinIdentity(transaction_identity):
    assert not issubclass(transaction_identity, MutableSerializableMeta),\
        "immutable idenity expected"

    for frontend, concrete in transaction_identity._clsmap.items():
        set_frontend_class(frontend, concrete, _thread_local)

    for frontend, concrete in \
            transaction_identity._mutable_identity._clsmap.items():
        set_frontend_class(frontend, concrete, _thread_local)


def _SetChainParams(params):
    _thread_local.chain_params = params
    _SetTransactionCoinIdentity(params.TRANSACTION_IDENTITY)


def _GetCurrentChainParams():
    return _thread_local.chain_params


_SetTransactionCoinIdentity(BitcoinTransactionIdentityMeta)

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
    'CBitcoinOutPoint',
    'CBitcoinMutableOutPoint',
    'CBitcoinTxIn',
    'CBitcoinMutableTxIn',
    'CBitcoinTxOut',
    'CBitcoinMutableTxOut',
    'CBitcoinTransaction',
    'CBitcoinMutableTransaction',
    'CBitcoinTxWitness',
    'CBitcoinMutableTxWitness',
    'CBitcoinMutableTxInWitness',
    'CBitcoinTxInWitness',
    'CheckTransactionError',
    'CheckTransaction',
    'GetLegacySigOpCount',
    'Uint256',
    'bytes_for_repr',
    'str_money_value_for_repr',
)
