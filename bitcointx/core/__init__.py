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

import threading
import binascii
import struct
from abc import abstractmethod
from io import BytesIO

from . import script

from .serialize import (
    ImmutableSerializable, make_mutable,
    BytesSerializer, VectorSerializer,
    ser_read, uint256_to_str, uint256_from_str,
    Hash, Hash160
)

from ..util import (
    no_bool_use_as_property, ClassMappingDispatcher, activate_class_dispatcher,
    dispatcher_wrap_methods, classgetter
)


_thread_local = threading.local()
_thread_local.mutable_context_enabled = False


class CoreCoinClassDispatcher(ClassMappingDispatcher, identity='core',
                              depends=[script.ScriptCoinClassDispatcher]):

    def __init_subclass__(mcs, **kwargs):
        return super().__init_subclass__(**kwargs)

    def __new__(mcs, name, bases, dct, mutable_of=None, **kwargs):
        return super().__new__(mcs, name, bases, dct, **kwargs)

    def __init__(cls, name, bases, dct, mutable_of=None, **kwargs):
        super().__init__(name, bases, dct, **kwargs)
        if mutable_of is None:
            cls._immutable_cls = cls
            cls._mutable_cls = None
        else:
            assert issubclass(mutable_of, CoreCoinClass)

            make_mutable(cls)

            cls._immutable_cls = mutable_of
            cls._mutable_cls = cls
            assert mutable_of._immutable_cls == mutable_of
            assert mutable_of._mutable_cls is None
            mutable_of._mutable_cls = cls

            # Wrap methods of a mutable class so that
            # inside the methods, mutable context is enabled.
            # When it is enabled, __call__ and __getattribute__
            # will substitute immutable class for its mutable twin.
            combined_dict = mutable_of.__dict__.copy()
            combined_dict.update(cls.__dict__)

            def wrap(fn, mcs):
                def wrapper(*args, **kwargs):
                    # We are about to call a method of a mutable class.
                    # enable the mutable context, but save previous state.
                    prev_state = _thread_local.mutable_context_enabled
                    _thread_local.mutable_context_enabled = True
                    try:
                        return fn(*args, **kwargs)
                    finally:
                        # After the method call, restore the context
                        _thread_local.mutable_context_enabled = prev_state

                return wrapper

            dispatcher_wrap_methods(cls, wrap, dct=combined_dict)

    def __call__(cls, *args, **kwargs):
        if _thread_local.mutable_context_enabled:
            cls = type.__getattribute__(cls, '_mutable_cls') or cls
        return super().__call__(*args, **kwargs)

    def __getattribute__(cls, name):
        if _thread_local.mutable_context_enabled:
            cls = type.__getattribute__(cls, '_mutable_cls') or cls
        return super().__getattribute__(name)


class CoreCoinClass(ImmutableSerializable, metaclass=CoreCoinClassDispatcher):

    def to_mutable(self):
        return self._mutable_cls.from_instance(self)

    def to_immutable(self):
        return self._immutable_cls.from_instance(self)

    @no_bool_use_as_property
    @classmethod
    def is_immutable(cls):
        return not cls.is_mutable()

    @no_bool_use_as_property
    @classmethod
    def is_mutable(cls):
        if cls is cls._mutable_cls:
            return True

        assert cls is cls._immutable_cls
        return False

    @classmethod
    def from_instance(cls, other_inst):
        if not isinstance(other_inst, cls._immutable_cls):
            raise ValueError(
                'incompatible class: expected instance of {}, got {}'
                .format(cls._immutable_cls.__name__,
                        other_inst.__class__.__name__))

        if cls.is_immutable() and other_inst.is_immutable():
            return other_inst

        return cls.clone_from_instance(other_inst)


class CoreBitcoinClassDispatcher(
    CoreCoinClassDispatcher, depends=[script.ScriptBitcoinClassDispatcher]
):
    ...


class CoreBitcoinClass(CoreCoinClass, metaclass=CoreBitcoinClassDispatcher):
    ...


class CoreCoinParams(CoreCoinClass):
    COIN = 100000000
    MAX_BLOCK_WEIGHT = 4000000
    WITNESS_SCALE_FACTOR = 4

    @classgetter
    def MAX_MONEY(cls):
        return 21000000 * cls.COIN


class CoreBitcoinParams(CoreCoinParams, CoreBitcoinClass):
    ...


def MoneyRange(nValue):
    return 0 <= nValue <= CoreCoinParams.MAX_MONEY


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
    COIN = CoreCoinParams.COIN
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


def coins_to_satoshi(value, check_range=True):
    """Simple utility function to convert from
    floating-point coins amount to integer satoshi amonut"""
    result = int(round(float(value) * CoreCoinParams.COIN))

    if check_range:
        if not MoneyRange(result):
            raise ValueError('resulting value ({}) is outside MoneyRange'
                             .format(result))

    return result


def satoshi_to_coins(value, check_range=True):
    """Simple utility function to convert from
    integer satoshi amonut to floating-point coins amount"""
    if check_range:
        if not MoneyRange(value):
            raise ValueError('supplied value ({}) is outside MoneyRange'
                             .format(value))
    return float(float(value) / CoreCoinParams.COIN)


def get_size_of_compact_size(size):
    # comment from GetSizeOfCompactSize() src/serialize.h in Bitcoin Core:
    #
    # Compact Size
    # size <  253        -- 1 byte
    # size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
    # size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
    # size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)

    if size < 0xFD:
        return 1
    elif size <= 0xFFFF:
        return 3
    elif size <= 0xFFFFFFFF:
        return 5
    else:
        return 9


def calculate_transaction_virtual_size(*,
                                       num_inputs,
                                       inputs_serialized_size,
                                       num_outputs,
                                       outputs_serialized_size,
                                       witness_size):

    """Calculate vsize of transaction given the number of inputs and
       outputs, the serialized size of inputs and outputs, and witness size.
       Useful for fee calculation at the time of coin selection, where you
       might not have CTransaction ready, but know all the parameters on
       that vsize depends on.

       Number of witnesses is always equal to number of inputs,
       and empty witnesses are encoded as a single zero byte.
       If there will be witnesses present in a transaction, `witness_size`
       must be larger than or equal to `num_inputs`.
       If the transaction will not include any witnesses, `witness_size`
       can be 0, or it can be equal to `num_inputs` (that is interpreted as
       'all witnesses are empty', and `witness_size` of 0 is used instead).
       Non-zero `witness_size` that is less than `num_inputs` is an error.

       Note that virtual size can also depend on number of sigops for the
       transaction, and this function does not account for this.

       In Bitcoin Core, virtual size is calculated as a maximum value
       between data-based calculated size and sigops-based calculated size.

       But for sigops-based size to be larger than data-based size, number
       of sigops have to be huge, and is unlikely to happen for normal scripts.
       Counting sigops also requires access to the inputs of the transaction,
       and the sigops-based size depends on adjustable parameter
       "-bytespersigop" in Bitcoin Core (default=20 for v0.18.1).

       If you care about sigops-based vsize and calculated your number of
       sigops, you can compare data-based size with your sigops-based size
       yourself, and use the maximum value. Do not forget that sigops-based
       size is also WITNESS_SCALE_FACTOR adjusted:
          (nSigOpCost * bytes_per_sigop
                      + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR

       """

    if witness_size != 0:
        if witness_size < num_inputs:
            raise ValueError(
                "witness_size should be >= num_inputs, "
                "because empty witness are encoded as a single zero byte.")
        if witness_size == num_inputs:
            # this can happen only if each witness is empty (single zero byte)
            # and therefore the transaction witness will be deemed empty,
            # and won't be serialized
            witness_size = 0
        else:
            # (marker byte, flag byte) that signal that the transaction
            # has witness present are included in witness size.
            witness_size += 2

    base_size = (
        4    # version
        + get_size_of_compact_size(num_inputs)
        + inputs_serialized_size
        + get_size_of_compact_size(num_outputs)
        + outputs_serialized_size
        + 4  # sequence
    )

    WITNESS_SCALE_FACTOR = CoreCoinParams.WITNESS_SCALE_FACTOR

    unscaled_size = (base_size * WITNESS_SCALE_FACTOR
                     + witness_size + WITNESS_SCALE_FACTOR-1)
    return unscaled_size // WITNESS_SCALE_FACTOR


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


class AddressDataEncodingError(Exception):
    """Base class for all errors related to address encoding"""


class ReprOrStrMixin():

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


class COutPoint(CoreCoinClass, next_dispatch_final=True):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__ = ['hash', 'n']

    def __init__(self, hash=b'\x00'*32, n=0xffffffff):
        if not len(hash) == 32:
            raise ValueError('%s: hash must be exactly 32 bytes; got %d bytes'
                             % (self.__class__.__name__, len(hash)))
        object.__setattr__(self, 'hash', hash)
        if not (0 <= n <= 0xffffffff):
            raise ValueError('%s: n must be in range 0x0 to 0xffffffff; got %x'
                             % (self.__class__.__name__, n))
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
    def clone_from_instance(cls, other):
        return cls(other.hash, other.n)

    @classmethod
    def from_outpoint(cls, outpoint):
        return cls.from_instance(outpoint)


class CMutableOutPoint(COutPoint, mutable_of=COutPoint,
                       next_dispatch_final=True):
    ...


class CBitcoinOutPoint(COutPoint, CoreBitcoinClass):
    """Bitcoin COutPoint"""
    __slots__ = []


class CBitcoinMutableOutPoint(CBitcoinOutPoint, CMutableOutPoint,
                              mutable_of=CBitcoinOutPoint):
    """A mutable Bitcoin COutPoint"""

    __slots__ = []


class CTxIn(CoreCoinClass, next_dispatch_final=True):
    """A base class for an input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence']

    def __init__(self, prevout=None, scriptSig=None, nSequence=0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        if scriptSig is None:
            scriptSig = script.CScript()
        elif not isinstance(scriptSig, script.CScript):
            assert isinstance(scriptSig, (bytes, bytearray)), scriptSig.__class__
            scriptSig = script.CScript(scriptSig)
        if prevout is None:
            prevout = COutPoint()
        elif self.is_mutable() or prevout.is_mutable():
            prevout = COutPoint.from_outpoint(prevout)
        object.__setattr__(self, 'nSequence', nSequence)
        object.__setattr__(self, 'prevout', prevout)
        object.__setattr__(self, 'scriptSig', scriptSig)

    @classmethod
    def stream_deserialize(cls, f):
        prevout = COutPoint.stream_deserialize(f)
        scriptSig = BytesSerializer.stream_deserialize(f)
        nSequence = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(prevout, scriptSig, nSequence)

    def stream_serialize(self, f):
        COutPoint.stream_serialize(self.prevout, f)
        BytesSerializer.stream_serialize(self.scriptSig, f)
        f.write(struct.pack(b"<I", self.nSequence))

    @no_bool_use_as_property
    def is_final(self):
        return (self.nSequence == 0xffffffff)

    @classmethod
    def clone_from_instance(cls, txin):
        return cls(
            COutPoint.from_outpoint(txin.prevout),
            txin.scriptSig, txin.nSequence)

    @classmethod
    def from_txin(cls, txin):
        """Create a mutable or immutable copy of an existing TxIn,
        depending on the class this method is called on.

        If cls and txin are both immutable, txin is returned directly.
        """
        return cls.from_instance(txin)

    def __repr__(self):
        return "%s(%s, %s, 0x%x)" % (
            self.__class__.__name__,
            repr(self.prevout), repr(self.scriptSig), self.nSequence)


class CMutableTxIn(CTxIn, mutable_of=CTxIn, next_dispatch_final=True):
    pass


class CBitcoinTxIn(CTxIn, CoreBitcoinClass):
    """An immutable Bitcoin TxIn"""
    __slots__ = []


class CBitcoinMutableTxIn(CBitcoinTxIn, CMutableTxIn, mutable_of=CBitcoinTxIn):
    """A mutable Bitcoin TxIn"""
    __slots__ = []


class CTxOut(CoreCoinClass, next_dispatch_final=True):
    """A base class for an output of a transaction

    Contains the public key that the next input must be able to sign with to
    claim it.
    """
    __slots__ = ['nValue', 'scriptPubKey']

    def __init__(self, nValue=-1, scriptPubKey=script.CScript()):
        if not isinstance(scriptPubKey, script.CScript):
            assert isinstance(scriptPubKey, (bytes, bytearray))
            scriptPubKey = script.CScript(scriptPubKey)
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
    def clone_from_instance(cls, txout):
        return cls(txout.nValue, txout.scriptPubKey)

    @classmethod
    def from_txout(cls, txout):
        return cls.from_instance(txout)


class CMutableTxOut(CTxOut, mutable_of=CTxOut, next_dispatch_final=True):
    pass


class CBitcoinTxOut(CTxOut, CoreBitcoinClass):
    """A immutable Bitcoin TxOut"""
    __slots__ = []


class CBitcoinMutableTxOut(CBitcoinTxOut, CMutableTxOut,
                           mutable_of=CBitcoinTxOut):
    """A mutable Bitcoin CTxOut"""
    __slots__ = []


class CTxInWitness(CoreCoinClass, next_dispatch_final=True):
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
    def clone_from_instance(cls, txin_witness):
        return cls(txin_witness.scriptWitness)

    @classmethod
    def from_txin_witness(cls, txin_witness):
        return cls.from_instance(txin_witness)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.scriptWitness))


class CMutableTxInWitness(CTxInWitness, mutable_of=CTxInWitness,
                          next_dispatch_final=True):
    pass


class CBitcoinTxInWitness(CTxInWitness, CoreBitcoinClass):
    """Immutable Bitcoin witness data for a single transaction input"""
    __slots__ = []


class CBitcoinMutableTxInWitness(CBitcoinTxInWitness, CMutableTxInWitness,
                                 mutable_of=CBitcoinTxInWitness):
    """Mutable Bitcoin witness data for a single transaction input"""
    __slots__ = []


class CTxOutWitness(CoreCoinClass, next_dispatch_final=True):
    pass


class CMutableTxOutWitness(CTxOutWitness, mutable_of=CTxOutWitness,
                           next_dispatch_final=True):
    pass


class _CBitcoinDummyTxOutWitness(CTxOutWitness, CoreBitcoinClass):
    pass


class _CBitcoinDummyMutableTxOutWitness(
    _CBitcoinDummyTxOutWitness, CMutableTxOutWitness,
    mutable_of=_CBitcoinDummyTxOutWitness
):
    pass


class CTxWitness(CoreCoinClass, next_dispatch_final=True):
    """Witness data for all inputs to a transaction"""
    __slots__ = ['vtxinwit']

    def __init__(self, vtxinwit=(), vtxoutwit=None):
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        txinwit = []
        for w in vtxinwit:
            txinwit.append(CTxInWitness.from_txin_witness(w))

        if self.is_immutable():
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
        vtxinwit = tuple(CTxInWitness.stream_deserialize(f)
                         for dummy in range(len(self.vtxinwit)))
        return self.__class__(vtxinwit)

    def stream_serialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].stream_serialize(f)

    @classmethod
    def clone_from_instance(cls, witness):
        vtxinwit = (CTxInWitness.from_txin_witness(w)
                    for w in witness.vtxinwit)
        return cls(vtxinwit)

    @classmethod
    def from_witness(cls, witness):
        return cls.from_instance(witness)

    def __repr__(self):
        return "%s([%s])" % (self.__class__.__name__,
                             ','.join(repr(w) for w in self.vtxinwit))


class CMutableTxWitness(CTxWitness, mutable_of=CTxWitness,
                        next_dispatch_final=True):
    pass


class CBitcoinTxWitness(CTxWitness, CoreBitcoinClass):
    """Immutable witness data for all inputs to a transaction"""
    __slots__ = []


class CBitcoinMutableTxWitness(CBitcoinTxWitness, CMutableTxWitness,
                               mutable_of=CBitcoinTxWitness):
    """Witness data for all inputs to a transaction, mutable version"""
    __slots__ = []


class CTransaction(ReprOrStrMixin, CoreCoinClass, next_dispatch_final=True):
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

        if witness is None or witness.is_null():
            if witness is None and self.is_immutable():
                witness = CTxWitness()
            else:
                witness = CTxWitness(
                    [CTxInWitness() for dummy in range(len(vin))],
                    [CTxOutWitness() for dummy in range(len(vout))])
        else:
            witness = CTxWitness.from_witness(witness)

        tuple_or_list = list if self.is_mutable() else tuple

        object.__setattr__(self, 'nLockTime', nLockTime)
        object.__setattr__(self, 'nVersion', nVersion)
        object.__setattr__(self, 'vin', tuple_or_list(
            CTxIn.from_txin(txin) for txin in vin))
        object.__setattr__(self, 'vout', tuple_or_list(
            CTxOut.from_txout(txout) for txout in vout))
        object.__setattr__(self, 'wit', witness)

    @no_bool_use_as_property
    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def has_witness(self):
        """True if witness"""
        return not self.wit.is_null()

    def _repr_or_str(self, strfn):
        return "%s(%s, %s, %i, %i, %s)" % (
            self.__class__.__name__,
            ', '.join(strfn(v) for v in self.vin), ', '.join(strfn(v) for v in self.vout),
            self.nLockTime, self.nVersion, strfn(self.wit))

    def GetTxid(self):
        """Get the transaction ID.  This differs from the transactions hash as
            given by GetHash.  GetTxid excludes witness data, while GetHash
            includes it. """

        if not self.wit.is_null():
            txid = Hash(CTransaction(
                self.vin, self.vout, self.nLockTime, self.nVersion).serialize())
        else:
            txid = Hash(self.serialize())
        return txid

    @classmethod
    def clone_from_instance(cls, tx):
        vin = [CTxIn.from_txin(txin) for txin in tx.vin]
        vout = [CTxOut.from_txout(txout)
                for txout in tx.vout]
        wit = CTxWitness.from_witness(tx.wit)
        return cls(vin, vout, tx.nLockTime, tx.nVersion, wit)

    @classmethod
    def from_tx(cls, tx):
        return cls.from_instance(tx)

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
            vin = VectorSerializer.stream_deserialize(f, element_class=CTxIn)
            vout = VectorSerializer.stream_deserialize(f, element_class=CTxOut)
            wit = CTxWitness(
                tuple(CTxInWitness() for dummy in range(len(vin))))
            wit = wit.stream_deserialize(f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion, wit)
        else:
            f.seek(pos)  # put marker byte back, since we don't have peek
            vin = VectorSerializer.stream_deserialize(f, element_class=CTxIn)
            vout = VectorSerializer.stream_deserialize(f, element_class=CTxOut)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion)

    # NOTE: for_sighash is ignored, but may be used in other implementations
    def stream_serialize(self, f, include_witness=True, for_sighash=False):
        f.write(struct.pack(b"<i", self.nVersion))
        if include_witness and not self.wit.is_null():
            assert(len(self.wit.vtxinwit) == len(self.vin))
            f.write(b'\x00')  # Marker
            f.write(b'\x01')  # Flag
            VectorSerializer.stream_serialize(self.vin, f)
            VectorSerializer.stream_serialize(self.vout, f)
            self.wit.stream_serialize(f)
        else:
            VectorSerializer.stream_serialize(self.vin, f)
            VectorSerializer.stream_serialize(self.vout, f)
        f.write(struct.pack(b"<I", self.nLockTime))

    def get_virtual_size(self):
        """Calculate virtual size for the transaction.

        Note that calculation does not take sigops into account.
        Sigops-based vsize is only relevant for highly non-standard
        scripts with very high sigop count, and cannot be directly deduced
        giving only the data of one transaction.

        see docstring for `calculate_transaction_virtual_size()`
        for more detailed explanation."""
        f = BytesIO()
        for vin in self.vin:
            vin.stream_serialize(f)
        inputs_size = len(f.getbuffer())
        f = BytesIO()
        for vout in self.vout:
            vout.stream_serialize(f)
        outputs_size = len(f.getbuffer())
        f = BytesIO()
        if self.wit.is_null():
            witness_size = 0
        else:
            self.wit.stream_serialize(f)
            witness_size = len(f.getbuffer())

        return calculate_transaction_virtual_size(
            num_inputs=len(self.vin),
            inputs_serialized_size=inputs_size,
            num_outputs=len(self.vout),
            outputs_serialized_size=outputs_size,
            witness_size=witness_size)


class CMutableTransaction(CTransaction, mutable_of=CTransaction,
                          next_dispatch_final=True):
    pass


class CBitcoinTransaction(CTransaction, CoreBitcoinClass):
    """Bitcoin transaction"""
    __slots__ = []


class CBitcoinMutableTransaction(CBitcoinTransaction, CMutableTransaction,
                                 mutable_of=CBitcoinTransaction):
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
    weight = (len(base_tx.serialize(include_witness=False))
              * CoreCoinParams.WITNESS_SCALE_FACTOR)
    if weight > CoreCoinParams.MAX_BLOCK_WEIGHT:
        raise CheckTransactionError("CheckTransaction() : size limits failed")

    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.vout:
        if txout.nValue < 0:
            raise CheckTransactionError("CheckTransaction() : txout.nValue negative")
        if txout.nValue > CoreCoinParams.MAX_MONEY:
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


def _SetChainParams(params):
    _thread_local.chain_params = params


def _get_current_chain_params():
    return _thread_local.chain_params


# default dispatcher for the module
activate_class_dispatcher(CoreBitcoinClassDispatcher)

__all__ = (
    'Hash',
    'Hash160',
    'MoneyRange',
    'x',
    'b2x',
    'lx',
    'b2lx',
    'str_money_value',
    'ValidationError',
    'AddressDataEncodingError',
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
    'satoshi_to_coins',
    'coins_to_satoshi',
    'get_size_of_compact_size',
    'calculate_transaction_virtual_size',
    'CoreCoinClassDispatcher',
    'CoreCoinClass',
    'CoreBitcoinClassDispatcher',
    'CoreBitcoinClass',
    'CoreCoinParams',
    'CoreBitcoinParams',
)
