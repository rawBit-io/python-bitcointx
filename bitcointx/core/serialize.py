# Copyright (C) 2012-2018 The python-bitcoinlib developers
# Copyright (C) 2019 The python-bitcointx developers
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

"""Serialization routines

You probabably don't need to use these directly.
"""

import hashlib
import struct

from io import BytesIO

MAX_SIZE = 0x02000000


def Hash(msg):
    """SHA256^2)(msg) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def Hash160(msg):
    """RIPEME160(SHA256(msg)) -> bytes"""
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(msg).digest())
    return h.digest()


class SerializationError(Exception):
    """Base class for serialization errors"""


class SerializationTruncationError(SerializationError):
    """Serialized data was truncated

    Thrown by deserialize() and stream_deserialize()
    """


class DeserializationExtraDataError(SerializationError):
    """Deserialized data had extra data at the end

    Thrown by deserialize() when not all data is consumed during
    deserialization. The deserialized object and extra padding not consumed are
    saved.
    """
    def __init__(self, msg, obj, padding):
        super().__init__(msg)
        self.obj = obj
        self.padding = padding


def ser_read(f, n):
    """Read from a stream safely

    Raises SerializationError and SerializationTruncationError appropriately.
    Use this instead of f.read() in your classes stream_(de)serialization()
    functions.
    """
    if n > MAX_SIZE:
        raise SerializationError('Asked to read 0x%x bytes; MAX_SIZE exceeded' % n)
    r = f.read(n)
    if len(r) < n:
        raise SerializationTruncationError('Asked to read %i bytes, but only got %i' % (n, len(r)))
    return r


class Serializable(object):
    """Base class for serializable objects"""

    __slots__ = []

    def stream_serialize(self, f, **kwargs):
        """Serialize to a stream"""
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f, **kwargs):
        """Deserialize from a stream"""
        raise NotImplementedError

    def serialize(self, **kwargs):
        """Serialize, returning bytes"""
        f = BytesIO()
        self.stream_serialize(f, **kwargs)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf, allow_padding=False, **kwargs):
        """Deserialize bytes, returning an instance

        allow_padding - Allow buf to include extra padding. (default False)

        If allow_padding is False and not all bytes are consumed during
        deserialization DeserializationExtraDataError will be raised.
        """
        fd = BytesIO(buf)
        r = cls.stream_deserialize(fd, **kwargs)
        if not allow_padding:
            padding = fd.read()
            if len(padding) != 0:
                raise DeserializationExtraDataError('Not all bytes consumed during deserialization',
                                                    r, padding)
        return r

    def GetHash(self):
        """Return the hash of the serialized object"""
        return Hash(self.serialize())

    def __eq__(self, other):
        if not isinstance(other, self.__class__)\
                and not isinstance(self, other.__class__):
            return NotImplemented
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.serialize())


class ImmutableSerializable(Serializable):
    """Immutable serializable object"""

    __slots__ = ['_cached_GetHash', '_cached__hash__']

    def __setattr__(self, name, value):
        raise AttributeError('Object is immutable')

    def __delattr__(self, name):
        raise AttributeError('Object is immutable')

    def GetHash(self):
        """Return the hash of the serialized object"""
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = super().GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

    def __hash__(self):
        try:
            return self._cached__hash__
        except AttributeError:
            _cached__hash__ = hash(self.serialize())
            object.__setattr__(self, '_cached__hash__', _cached__hash__)
            return _cached__hash__


class Serializer(object):
    """Base class for object serializers"""
    def __new__(cls):
        raise NotImplementedError

    @classmethod
    def stream_serialize(cls, obj, f):
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f):
        raise NotImplementedError

    @classmethod
    def serialize(cls, obj):
        f = BytesIO()
        cls.stream_serialize(obj, f)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf):
        if isinstance(buf, str) or isinstance(buf, (bytes, bytearray)):
            buf = BytesIO(buf)
        return cls.stream_deserialize(buf)


class VarIntSerializer(Serializer):
    """Serialization of variable length ints"""
    @classmethod
    def stream_serialize(cls, i, f):
        if i < 0:
            raise ValueError('varint must be non-negative integer')
        elif i < 0xfd:
            f.write(bytes([i]))
        elif i <= 0xffff:
            f.write(bytes([0xfd]))
            f.write(struct.pack(b'<H', i))
        elif i <= 0xffffffff:
            f.write(bytes([0xfe]))
            f.write(struct.pack(b'<I', i))
        else:
            f.write(bytes([0xff]))
            f.write(struct.pack(b'<Q', i))

    @classmethod
    def stream_deserialize(cls, f):
        r = ser_read(f, 1)[0]
        if r < 0xfd:
            return r
        elif r == 0xfd:
            return struct.unpack(b'<H', ser_read(f, 2))[0]
        elif r == 0xfe:
            return struct.unpack(b'<I', ser_read(f, 4))[0]
        else:
            return struct.unpack(b'<Q', ser_read(f, 8))[0]


class BytesSerializer(Serializer):
    """Serialization of bytes instances"""
    @classmethod
    def stream_serialize(cls, b, f):
        VarIntSerializer.stream_serialize(len(b), f)
        f.write(b)

    @classmethod
    def stream_deserialize(cls, f):
        datalen = VarIntSerializer.stream_deserialize(f)
        return ser_read(f, datalen)


class VectorSerializer(Serializer):
    """Base class for serializers of object vectors"""

    @classmethod
    def stream_serialize(cls, objs, f, **kwargs):
        VarIntSerializer.stream_serialize(len(objs), f)
        if not len(objs):
            return
        inner_cls = type(objs[0])
        for obj in objs:
            if type(obj) is not inner_cls:
                raise ValueError(
                    'supplied objects are of different types, '
                    'first object is of type {}, but there is also an object '
                    'of type {}'.format(inner_cls.__name__, type(obj).__name__))
            inner_cls.stream_serialize(obj, f, **kwargs)

    @classmethod
    def stream_deserialize(cls, f, element_class=None, **kwargs):
        assert element_class is not None,\
            "The class of the elements in the vector must be supplied"
        n = VarIntSerializer.stream_deserialize(f)
        r = []
        for i in range(n):
            r.append(element_class.stream_deserialize(f, **kwargs))
        return r


class uint256VectorSerializer(Serializer):
    """Serialize vectors of uint256"""
    @classmethod
    def stream_serialize(cls, uints, f):
        VarIntSerializer.stream_serialize(len(uints), f)
        for uint in uints:
            assert len(uint) == 32
            f.write(uint)

    @classmethod
    def stream_deserialize(cls, f):
        n = VarIntSerializer.stream_deserialize(f)
        r = []
        for i in range(n):
            r.append(ser_read(f, 32))
        return r


class intVectorSerializer(Serializer):

    @classmethod
    def stream_serialize(cls, ints, f):
        datalen = len(ints)
        VarIntSerializer.stream_serialize(datalen, f)
        for i in ints:
            f.write(struct.pack(b"<i", i))

    @classmethod
    def stream_deserialize(cls, f):
        datalen = VarIntSerializer.stream_deserialize(f)
        ints = []
        for i in range(datalen):
            ints.append(struct.unpack(b"<i", ser_read(f, 4))[0])
        return ints


class VarStringSerializer(Serializer):
    """Serialize variable length byte strings"""
    @classmethod
    def stream_serialize(cls, s, f):
        datalen = len(s)
        VarIntSerializer.stream_serialize(datalen, f)
        f.write(s)

    @classmethod
    def stream_deserialize(cls, f):
        datalen = VarIntSerializer.stream_deserialize(f)
        return ser_read(f, datalen)


def uint256_from_str(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_to_str(u):
    r = b""
    for i in range(8):
        r += struct.pack('<I', u >> (i * 32) & 0xffffffff)
    return r


def uint256_to_shortstr(u):
    s = "%064x" % (u,)
    return s[:16]


def make_mutable(cls):
    assert issubclass(cls, ImmutableSerializable), \
        ("make_mutable can only be applied to subclasses "
            "of ImmutableSerializable")
    # For speed we use a class decorator that removes the immutable
    # restrictions directly. In addition the modified behavior of GetHash() and
    # hash() is undone.
    cls.__setattr__ = object.__setattr__
    cls.__delattr__ = object.__delattr__
    cls.GetHash = Serializable.GetHash
    cls.__hash__ = Serializable.__hash__
    return cls


__all__ = (
    'MAX_SIZE',
    'Hash',
    'Hash160',
    'SerializationError',
    'SerializationTruncationError',
    'DeserializationExtraDataError',
    'ser_read',
    'Serializable',
    'ImmutableSerializable',
    'Serializer',
    'VarIntSerializer',
    'BytesSerializer',
    'VectorSerializer',
    'uint256VectorSerializer',
    'intVectorSerializer',
    'VarStringSerializer',
    'uint256_from_str',
    'uint256_to_str',
    'uint256_to_shortstr',
    'make_mutable',
)
