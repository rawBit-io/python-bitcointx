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

# pylama:ignore=C901,E221

from typing import (
    TypeVar, Tuple, List, Dict, Set, Union, Type, Any, Optional, Generator,
    NamedTuple
)

import struct
from enum import Enum
from collections import OrderedDict

from .serialize import (
    BytesSerializer, VarIntSerializer, ByteStream_Type, SerializationError,
    SerializationTruncationError, ser_read, Serializable
)
from . import CTransaction, CTxOut, b2x
from .key import CPubKey, BIP32Path
from .script import (
    CScript, CScriptWitness, KNOWN_SIGHASH_BITFLAGS, KNOWN_SIGHASH_TYPES
)
from ..wallet import CCoinExtPubKey

from ..util import ensure_isinstance, no_bool_use_as_property

PSBT_MAGIC_HEADER_BYTES = b'psbt\xff'
PSBT_SEPARATOR = b'\x00'

PSBT_PROPRIETARY_TYPE = 0xFC


class PSBT_GlobalKeyType(Enum):
    UNSIGNED_TX = 0x00
    XPUB        = 0x01
    VERSION     = 0xFB


class PSBT_InKeyType(Enum):
    NON_WITNESS_UTXO    = 0x00
    WITNESS_UTXO        = 0x01
    PARTIAL_SIG         = 0x02
    SIGHASH_TYPE        = 0x03
    REDEEM_SCRIPT       = 0x04
    WITNESS_SCRIPT      = 0x05
    BIP32_DERIVATION    = 0x06
    FINAL_SCRIPTSIG     = 0x07
    FINAL_SCRIPTWITNESS = 0x08
    POR_COMMITMENT      = 0x09


class PSBT_OutKeyType(Enum):
    REDEEM_SCRIPT    = 0x00
    WITNESS_SCRIPT   = 0x01
    BIP32_DERIVATION = 0x02


PSBT_ProprietaryTypeData = NamedTuple(
    'PSBT_ProprietaryTypeData', [
        ('subtype', int), ('key_data', bytes), ('value', bytes)
    ])

PSBT_UnknownTypeData = NamedTuple(
    'PSBT_UnknownTypeData', [
        ('key_type', int), ('key_data', bytes), ('value', bytes)
    ])

T_KeyTypeEnum_Type = Union[
    Type[PSBT_GlobalKeyType],
    Type[PSBT_OutKeyType],
    Type[PSBT_InKeyType],
]

T_KeyTypeEnum = Union[PSBT_GlobalKeyType, PSBT_OutKeyType, PSBT_InKeyType]


def proprietary_field_repr(
    prop_fields_dict: Dict[bytes, List[PSBT_ProprietaryTypeData]]
) -> str:
    def prop_str(p_list: List[PSBT_ProprietaryTypeData]) -> str:
        return ', '.join(
            f"({v.subtype}, x('{b2x(v.key_data)}'), x('{b2x(v.value)}'))"
            for v in p_list)

    return ', '.join(f"x('{b2x(k)}'): ({prop_str(v)})"
                     for k, v in prop_fields_dict.items())


def unknown_fields_repr(unknown_fields: List[PSBT_UnknownTypeData]) -> str:
    return ', '.join(
        f"({v.key_type}, x('{b2x(v.key_data)}'), x('{b2x(v.value)}'))"
        for v in unknown_fields)


def derivation_repr(
    derivation: Dict[CPubKey, 'PSBT_KeyDerivationInfo']
) -> str:
    return (', '.join(
        f"x('{b2x(k)}'): (x('{b2x(v.fingerprint)}'), \"{str(v.path)}\")"
        for k, v in derivation.items()))


def stream_serialize_field(
    key_type: Union[int, T_KeyTypeEnum],
    f: ByteStream_Type,
    key_data: bytes = b'',
    value: bytes = b''
) -> None:
    key_type_value = key_type if isinstance(key_type, int) else key_type.value
    key = VarIntSerializer.serialize(key_type_value) + key_data
    BytesSerializer.stream_serialize(key, f)
    BytesSerializer.stream_serialize(value, f)


def stream_serialize_proprietary_fields(
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]],
    f: ByteStream_Type,
) -> None:
    for prefix in proprietary_fields.keys():
        for prop_data in proprietary_fields[prefix]:
            prop_key = (
                BytesSerializer.serialize(prefix)
                + VarIntSerializer.serialize(prop_data.subtype)
                + prop_data.key_data
            )
            stream_serialize_field(PSBT_PROPRIETARY_TYPE, f,
                                   key_data=prop_key, value=prop_data.value)


def stream_serialize_unknown_fields(
    unknown_fields: List[PSBT_UnknownTypeData],
    f: ByteStream_Type,
) -> None:
    for unk_data in unknown_fields:
        stream_serialize_field(unk_data.key_type, f,
                               key_data=unk_data.key_data,
                               value=unk_data.value)


def read_psbt_keymap(
    f: ByteStream_Type,
    keys_seen: Set[bytes],
    keys_enum_class: T_KeyTypeEnum_Type,
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]],
    unknown_fields: List[PSBT_UnknownTypeData]
) -> Generator[Tuple[T_KeyTypeEnum, bytes, bytes], None, None]:
    while True:
        key_data = BytesSerializer.stream_deserialize(f)
        if not key_data:
            return

        if key_data in keys_seen:
            raise SerializationError(
                f'Duplicate key encountered at position {f.tell()}')

        keys_seen.add(key_data)

        key_type, key_data = VarIntSerializer.deserialize_partial(key_data)

        value = BytesSerializer.stream_deserialize(f)

        if key_type == PSBT_PROPRIETARY_TYPE:
            prefix, tail = BytesSerializer.deserialize_partial(key_data)
            subtype, key_data = VarIntSerializer.deserialize_partial(tail)
            field = PSBT_ProprietaryTypeData(
                subtype=subtype, key_data=key_data, value=value)
            if prefix in proprietary_fields:
                proprietary_fields[prefix].append(field)
            else:
                proprietary_fields[prefix] = [field]

            continue

        try:
            kt = keys_enum_class(key_type)
        except ValueError:
            unknown_fields.append(
                PSBT_UnknownTypeData(key_type=key_type, key_data=key_data,
                                     value=value))
            continue

        yield kt, key_data, value


def ensure_empty_key_data(
    key_type: T_KeyTypeEnum, key_data: bytes, msg_suffix: str = ''
) -> None:
    if key_data:
        raise SerializationError(
            f'Unexpected data after key type {key_type.name}' + msg_suffix)


T_PSBT_KeyDerivationInfo = TypeVar('T_PSBT_KeyDerivationInfo',
                                   bound='PSBT_KeyDerivationInfo')


class PSBT_KeyDerivationInfo(Serializable):
    fingerprint: bytes
    path: BIP32Path

    def __init__(self, *, fingerprint: bytes, path: BIP32Path) -> None:
        ensure_isinstance(fingerprint, bytes, 'key fingerprint')
        ensure_isinstance(path, BIP32Path, 'bip32 path')
        if len(fingerprint) != 4:
            raise ValueError('Fingerprint should be 4 bytes in length')
        self.fingerprint = fingerprint
        self.path = path

    @classmethod
    def stream_deserialize(cls: Type[T_PSBT_KeyDerivationInfo],
                           f: ByteStream_Type,
                           _err_msg_suffix: str = '', **kwargs: Any
                           ) -> T_PSBT_KeyDerivationInfo:
        fingerprint = ser_read(f, 4)
        indexlist: List[int] = []
        while(True):
            data = f.read(4)
            if len(data) < 4:
                if len(data):
                    raise SerializationTruncationError(
                        'Reached end of data while trying to read next '
                        'derivation index' + _err_msg_suffix)
                # reached end of data and have successfully read all indexes
                break

            indexlist.append(struct.unpack(b"<I", data)[0])

            if len(indexlist) > 255:
                raise ValueError(
                    'Derivation path longer than 255 elements'
                    + _err_msg_suffix)

        return cls(fingerprint=fingerprint, path=BIP32Path(indexlist))

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        f.write(self.fingerprint)
        for index in self.path:
            f.write(struct.pack(b"<I", index))


T_PSBT_Input = TypeVar('T_PSBT_Input', bound='PSBT_Input')


class PSBT_Input(Serializable):
    utxo: Optional[Union[CTransaction, CTxOut]]
    partial_sigs: Dict[CPubKey, bytes]
    sighash_type: Optional[int]
    redeem_script: CScript
    witness_script: CScript
    derivation: Dict[CPubKey, PSBT_KeyDerivationInfo]
    final_script_sig: bytes
    final_script_witness: CScriptWitness
    proof_of_reserves_commitment: bytes
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]]
    unknown_fields: List[PSBT_UnknownTypeData]

    def __init__(
        self, *,
        utxo: Optional[Union[CTransaction, CTxOut]] = None,
        partial_sigs: Dict[CPubKey, bytes] = OrderedDict(),
        sighash_type: Optional[int] = None,
        redeem_script: CScript = CScript(),
        witness_script: CScript = CScript(),
        derivation: Dict[CPubKey, PSBT_KeyDerivationInfo] = OrderedDict(),
        final_script_sig: bytes = b'',
        final_script_witness: CScriptWitness = CScriptWitness(),
        proof_of_reserves_commitment: bytes = b'',
        proprietary_fields: Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ] = OrderedDict(),
        unknown_fields: List[PSBT_UnknownTypeData] = [],

        allow_unknown_sighash_types: bool = False,
        _input_index: Optional[int] = None
    ) -> None:
        def descr(msg: str) -> str:
            if _input_index is not None:
                return f'{msg} for input at index {_input_index}'
            return msg

        if utxo is not None:
            ensure_isinstance(utxo, (CTransaction, CTxOut), descr('utxo'))
            if isinstance(utxo, CTxOut) and not utxo.is_valid():
                raise ValueError('Invalid CTxOut provided for utxo')

        self.utxo = utxo

        for pub, sig in partial_sigs.items():
            ensure_isinstance(
                pub, CPubKey,
                descr('pubkey for one of the partial signatures'))
            ensure_isinstance(sig, bytes,
                              descr('one of the partial signatures'))
        self.partial_sigs = partial_sigs

        if sighash_type is not None:
            ensure_isinstance(sighash_type, int, descr('sighash type'))
            if not allow_unknown_sighash_types:
                if (sighash_type & ~KNOWN_SIGHASH_BITFLAGS) \
                        not in KNOWN_SIGHASH_TYPES:
                    raise ValueError(
                        descr(f'Unknown sighash type 0x{sighash_type:x}'))
            elif 2**32 <= sighash_type < 0:
                raise ValueError(descr('Sighash type out of range '))

        self.sighash_type = sighash_type

        ensure_isinstance(redeem_script, CScript, descr('redeem script'))
        self.redeem_script = redeem_script

        ensure_isinstance(witness_script, CScript, descr('witness script'))
        self.witness_script = witness_script

        for pub, derinfo in derivation.items():
            ensure_isinstance(pub, CPubKey,
                              descr('one of pubkeys in bip32 derivation'))
            ensure_isinstance(derinfo, PSBT_KeyDerivationInfo,
                              descr('derivation info for one of pubkeys'))

        self.derivation = derivation

        ensure_isinstance(final_script_sig, bytes, descr('final script sig'))
        self.final_script_sig = final_script_sig

        ensure_isinstance(final_script_witness, CScriptWitness,
                          descr('final script witness'))
        self.final_script_witness = final_script_witness

        ensure_isinstance(proof_of_reserves_commitment,
                          bytes, descr('proof of reserves commitment'))
        self.proof_of_reserves_commitment = proof_of_reserves_commitment

        for prefix, p_fields in proprietary_fields.items():
            ensure_isinstance(prefix, bytes, descr('proprietary type prefix'))
            for field_index, field in enumerate(p_fields):
                ensure_isinstance(
                    field, PSBT_ProprietaryTypeData,
                    descr(f'one of proprietary field contents for '
                          f'prefix {b2x(prefix)}'))

        self.proprietary_fields = proprietary_fields

        for u_field in unknown_fields:
            ensure_isinstance(u_field, PSBT_UnknownTypeData,
                              descr('contents of unkown type'))
        self.unknown_fields = unknown_fields

        self._check_sanity()

    def _check_sanity(self) -> None:
        if self.witness_script and not isinstance(self.utxo, CTxOut):
            raise ValueError(
                'Witness_script is present, utxo should be witness utxo')

        if not self.final_script_witness.is_null() \
                and not isinstance(self.utxo, CTxOut):
            raise ValueError(
                'Final_script_witness is present, utxo should be witness utxo')

    @no_bool_use_as_property
    def is_null(self):
        return (
            self.utxo is None
            and not(self.partial_sigs)
            and not(self.redeem_script)
            and not(self.witness_script)
            and not(self.derivation)
            and not(self.final_script_sig)
            and self.final_script_witness.is_null()
            and not(self.proprietary_fields)
            and not(self.unknown_fields)
        )

    @classmethod
    def stream_deserialize(cls: Type[T_PSBT_Input], f: ByteStream_Type,
                           allow_unknown_sighash_types: bool = False,
                           _input_index: Optional[int] = None,
                           **kwargs: Any) -> T_PSBT_Input:

        utxo: Optional[Union[CTransaction, CTxOut]] = None
        partial_sigs: Dict[CPubKey, bytes] = OrderedDict()
        sighash_type: Optional[int] = None
        redeem_script: CScript = CScript()
        witness_script: CScript = CScript()
        derivation: Dict[CPubKey, PSBT_KeyDerivationInfo] = OrderedDict()
        final_script_sig: bytes = b''
        final_script_witness: CScriptWitness = CScriptWitness()
        proof_of_reserves_commitment: bytes = b''
        proprietary_fields: Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ] = OrderedDict()
        unknown_fields: List[PSBT_UnknownTypeData] = []

        def descr(msg: str) -> str:
            return f'{msg} for input at index {_input_index}'

        keys_seen: Set[bytes] = set()
        for key_type, key_data, value in \
                read_psbt_keymap(f, keys_seen, PSBT_InKeyType,
                                 proprietary_fields, unknown_fields):

            if key_type is PSBT_InKeyType.NON_WITNESS_UTXO:
                ensure_empty_key_data(key_type, key_data, descr(''))
                if utxo is not None:
                    raise SerializationError(
                        descr(
                            'Non-witness UTXO encountered after witness UTXO '
                            'already seen for the same input'))
                utxo = CTransaction.deserialize(value)
            elif key_type is PSBT_InKeyType.WITNESS_UTXO:
                ensure_empty_key_data(key_type, key_data, descr(''))
                if utxo is not None:
                    raise SerializationError(
                        descr(
                            'Non-witness UTXO encountered after witness UTXO '
                            'already seen for the same input'))
                utxo = CTxOut.deserialize(value)
            elif key_type is PSBT_InKeyType.PARTIAL_SIG:
                pub = CPubKey(key_data)
                if not pub.is_fullyvalid():
                    raise SerializationError(
                        descr(
                            f'Invalid pubkey encountered in {key_type.name}'))
                assert pub not in partial_sigs,\
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                partial_sigs[pub] = value
            elif key_type is PSBT_InKeyType.SIGHASH_TYPE:
                ensure_empty_key_data(key_type, key_data, descr(''))
                if len(value) != 4:
                    raise SerializationError(
                        descr('Incorrect data length for {key_type.name}'))
                sighash_type = struct.unpack(b"<I", value)[0]
            elif key_type is PSBT_InKeyType.REDEEM_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                redeem_script = CScript(value)
            elif key_type is PSBT_InKeyType.WITNESS_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                witness_script = CScript(value)
            elif key_type is PSBT_InKeyType.BIP32_DERIVATION:
                pub = CPubKey(key_data)
                if not pub.is_fullyvalid():
                    raise SerializationError(
                        descr(
                            f'Invalid pubkey encountered in {key_type.name}'))
                assert pub not in derivation,\
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                derivation[pub] = PSBT_KeyDerivationInfo.deserialize(value)
            elif key_type is PSBT_InKeyType.FINAL_SCRIPTSIG:
                ensure_empty_key_data(key_type, key_data, descr(''))
                final_script_sig = value
            elif key_type is PSBT_InKeyType.FINAL_SCRIPTWITNESS:
                ensure_empty_key_data(key_type, key_data, descr(''))
                final_script_witness = CScriptWitness.deserialize(value)
            elif key_type is PSBT_InKeyType.POR_COMMITMENT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                proof_of_reserves_commitment = value
            else:
                raise AssertionError(
                    f'If key type {key_type} is recognized, '
                    f'it must be handled, and this statement '
                    f'should not be reached.')

        return cls(utxo=utxo, partial_sigs=partial_sigs,
                   sighash_type=sighash_type,
                   redeem_script=redeem_script, witness_script=witness_script,
                   derivation=derivation,
                   final_script_sig=final_script_sig,
                   final_script_witness=final_script_witness,
                   proof_of_reserves_commitment=proof_of_reserves_commitment,
                   proprietary_fields=proprietary_fields,
                   unknown_fields=unknown_fields,
                   allow_unknown_sighash_types=allow_unknown_sighash_types,
                   _input_index=_input_index)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        if self.utxo is not None:
            if isinstance(self.utxo, CTransaction):
                stream_serialize_field(PSBT_InKeyType.NON_WITNESS_UTXO, f,
                                       value=self.utxo.serialize())
            elif isinstance(self.utxo, CTxOut):
                assert self.utxo.is_valid()
                stream_serialize_field(PSBT_InKeyType.WITNESS_UTXO, f,
                                       value=self.utxo.serialize())
            else:
                raise AssertionError(
                    'Expected utxo to be an instance CTransaction or CTxOut, '
                    f'not {self.utxo.__class__.__name__}')

        if not self.final_script_sig and self.final_script_witness.is_null():
            for pub, sig in self.partial_sigs.items():
                stream_serialize_field(PSBT_InKeyType.PARTIAL_SIG, f,
                                       key_data=pub, value=sig)

            if self.sighash_type is not None:
                stream_serialize_field(
                    PSBT_InKeyType.SIGHASH_TYPE, f,
                    value=struct.pack(b"<I", self.sighash_type))

            if self.redeem_script:
                stream_serialize_field(PSBT_InKeyType.REDEEM_SCRIPT, f,
                                       value=self.redeem_script)

            if self.witness_script:
                stream_serialize_field(PSBT_InKeyType.WITNESS_SCRIPT, f,
                                       value=self.witness_script)

            for pub, derinfo in self.derivation.items():
                stream_serialize_field(PSBT_InKeyType.BIP32_DERIVATION, f,
                                       key_data=pub, value=derinfo.serialize())

        if self.final_script_sig:
            stream_serialize_field(PSBT_InKeyType.FINAL_SCRIPTSIG, f,
                                   value=self.final_script_sig)

        if not self.final_script_witness.is_null():
            stream_serialize_field(PSBT_InKeyType.FINAL_SCRIPTWITNESS, f,
                                   value=self.final_script_witness.serialize())

        if self.proof_of_reserves_commitment:
            stream_serialize_field(PSBT_InKeyType.POR_COMMITMENT, f,
                                   value=self.proof_of_reserves_commitment)

        stream_serialize_proprietary_fields(self.proprietary_fields, f)
        stream_serialize_unknown_fields(self.unknown_fields, f)

        f.write(PSBT_SEPARATOR)

    def __repr__(self) -> str:
        partial_sigs = (', '.join(f"x('{b2x(k)}'): x('{b2x(v)}')"
                                  for k, v in self.partial_sigs.items()))
        return (
            f"{self.__class__.__name__}(utxo={self.utxo}, "
            f"partial_sigs={{{partial_sigs}}}, "
            f"sighash_type={self.sighash_type}, "
            f"redeem_script={repr(self.redeem_script)}, "
            f"witness_script={repr(self.witness_script)}, "
            f"derivation={{{derivation_repr(self.derivation)}}}, "
            f"final_script_sig=x('{b2x(self.final_script_sig)}'), "
            f"final_script_witness={repr(self.final_script_witness)}, "
            f"proof_of_reserves_commitment="
            f"x('{b2x(self.proof_of_reserves_commitment)}'), "
            f"proprietary_fields="
            f"{{{proprietary_field_repr(self.proprietary_fields)}}}, "
            f"unknown_fields=[{unknown_fields_repr(self.unknown_fields)}]"
            f")"
        )


T_PSBT_Output = TypeVar('T_PSBT_Output', bound='PSBT_Output')


class PSBT_Output(Serializable):
    redeem_script: CScript
    witness_script: CScript
    derivation: Dict[CPubKey, PSBT_KeyDerivationInfo]
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]]
    unknown_fields: List[PSBT_UnknownTypeData]

    def __init__(
        self, *,
        redeem_script: CScript = CScript(),
        witness_script: CScript = CScript(),
        derivation: Dict[CPubKey, PSBT_KeyDerivationInfo] = OrderedDict(),
        proprietary_fields: Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ] = OrderedDict(),
        unknown_fields: List[PSBT_UnknownTypeData] = [],

        _output_index: Optional[int] = None
    ) -> None:
        def descr(msg: str) -> str:
            if _output_index is not None:
                return f'{msg} for output at index {_output_index}'
            return msg

        ensure_isinstance(redeem_script, CScript, descr('redeem script'))
        self.redeem_script = redeem_script

        ensure_isinstance(witness_script, CScript, descr('witness script'))
        self.witness_script = witness_script

        for pub, derinfo in derivation.items():
            ensure_isinstance(pub, CPubKey,
                              descr('one of pubkeys in bip32 derivation'))
            ensure_isinstance(derinfo, PSBT_KeyDerivationInfo,
                              descr('derivation info for one of pubkeys'))

        self.derivation = derivation

        for prefix, p_fields in proprietary_fields.items():
            ensure_isinstance(prefix, bytes, descr('proprietary type prefix'))
            for field_index, field in enumerate(p_fields):
                ensure_isinstance(
                    field, PSBT_ProprietaryTypeData,
                    descr(f'one of proprietary field contents for '
                          f'prefix {b2x(prefix)}'))

        self.proprietary_fields = proprietary_fields

        for u_field in unknown_fields:
            ensure_isinstance(u_field, PSBT_UnknownTypeData,
                              descr('contents of unkown type'))
        self.unknown_fields = unknown_fields

        self._check_sanity()

    def _check_sanity(self) -> None:
        pass

    @no_bool_use_as_property
    def is_null(self):
        return (
            not(self.redeem_script)
            and not(self.witness_script)
            and not(self.derivation)
            and not(self.proprietary_fields)
            and not(self.unknown_fields)
        )

    @classmethod
    def stream_deserialize(cls: Type[T_PSBT_Output], f: ByteStream_Type,
                           _output_index: Optional[int] = None,
                           **kwargs: Any) -> T_PSBT_Output:

        redeem_script: CScript = CScript()
        witness_script: CScript = CScript()
        derivation: Dict[CPubKey, PSBT_KeyDerivationInfo] = OrderedDict()
        proprietary_fields: Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ] = OrderedDict()
        unknown_fields: List[PSBT_UnknownTypeData] = []

        def descr(msg: str) -> str:
            return f'{msg} for output at index {_output_index}'

        keys_seen: Set[bytes] = set()
        for key_type, key_data, value in \
                read_psbt_keymap(f, keys_seen, PSBT_OutKeyType,
                                 proprietary_fields, unknown_fields):

            if key_type == PSBT_OutKeyType.REDEEM_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                redeem_script = CScript(value)
            elif key_type == PSBT_OutKeyType.WITNESS_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                redeem_script = CScript(value)
            elif key_type == PSBT_OutKeyType.BIP32_DERIVATION:
                pub = CPubKey(key_data)
                if not pub.is_fullyvalid():
                    raise SerializationError(
                        descr(
                            f'Invalid pubkey encountered in {key_type.name}'))
                assert pub not in derivation,\
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                derivation[pub] = PSBT_KeyDerivationInfo.deserialize(value)

        return cls(redeem_script=redeem_script, witness_script=witness_script,
                   derivation=derivation,
                   proprietary_fields=proprietary_fields,
                   unknown_fields=unknown_fields,
                   _output_index=_output_index)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        if self.redeem_script:
            stream_serialize_field(PSBT_OutKeyType.REDEEM_SCRIPT, f,
                                   value=self.redeem_script)

        if self.witness_script:
            stream_serialize_field(PSBT_OutKeyType.WITNESS_SCRIPT, f,
                                   value=self.witness_script)

        for pub, derinfo in self.derivation.items():
            stream_serialize_field(PSBT_OutKeyType.BIP32_DERIVATION, f,
                                   key_data=pub, value=derinfo.serialize())

        stream_serialize_proprietary_fields(self.proprietary_fields, f)
        stream_serialize_unknown_fields(self.unknown_fields, f)

        f.write(PSBT_SEPARATOR)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"redeem_script={self.redeem_script}, "
            f"witness_script={self.witness_script}, "
            f"derivation={{{derivation_repr(self.derivation)}}}, "
            f"proprietary_fields="
            f"{{{proprietary_field_repr(self.proprietary_fields)}}}, "
            f"unknown_fields=[{unknown_fields_repr(self.unknown_fields)}]"
            f")"
        )


T_PartiallySigned_Transaction = TypeVar('T_PartiallySigned_Transaction',
                                        bound='PartiallySignedTransaction')


class PartiallySignedTransaction(Serializable):
    version: int
    inputs: List[PSBT_Input]
    outputs: List[PSBT_Output]
    unsigned_tx: CTransaction
    xpubs: Dict[CCoinExtPubKey, PSBT_KeyDerivationInfo]
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]]
    unknown_fields: List[PSBT_UnknownTypeData]

    def __init__(self, *,
                 version: int = 0,
                 inputs: List[PSBT_Input] = [],
                 outputs: List[PSBT_Output] = [],
                 unsigned_tx: CTransaction = CTransaction(),
                 xpubs: Dict[
                     CCoinExtPubKey, PSBT_KeyDerivationInfo
                 ] = OrderedDict(),
                 proprietary_fields: Dict[
                     bytes, List[PSBT_ProprietaryTypeData]
                 ] = OrderedDict(),
                 unknown_fields: List[PSBT_UnknownTypeData] = []
                 ) -> None:

        ensure_isinstance(version, int, 'version')
        if version != 0:
            raise ValueError('Unsupported PSBT version')
        self.version = version

        for i, inp in enumerate(inputs):
            ensure_isinstance(inp, PSBT_Input, f'input at position {i}')
        self.inputs = inputs

        for i, outp in enumerate(outputs):
            ensure_isinstance(outp, PSBT_Output, f'output at position {i}')
        self.outputs = outputs

        ensure_isinstance(unsigned_tx, CTransaction, 'unsigned_tx')
        if unsigned_tx.has_witness():
            raise ValueError(
                'Unsigned transaction contains witness data')
        if any(inp.scriptSig for inp in unsigned_tx.vin):
            raise ValueError(
                'Unsigned transaction contains non-empty scriptSigs')
        self.unsigned_tx = unsigned_tx

        for xpub, derinfo in xpubs.items():
            ensure_isinstance(xpub, CCoinExtPubKey, 'one of xpubs')
            ensure_isinstance(derinfo, PSBT_KeyDerivationInfo,
                              f'derivation info for one of xpubs')
        self.xpubs = xpubs

        for prefix, p_fields in proprietary_fields.items():
            ensure_isinstance(prefix, bytes, 'proprietary type prefix')
            for field_index, field in enumerate(p_fields):
                ensure_isinstance(
                    field, PSBT_ProprietaryTypeData,
                    f'one of proprietary field contents for '
                    f'prefix {b2x(prefix)}')

        self.proprietary_fields = proprietary_fields

        for u_field in unknown_fields:
            ensure_isinstance(u_field, PSBT_UnknownTypeData,
                              'contents of unkown type')
        self.unknown_fields = unknown_fields

        self._check_sanity()

    def _check_sanity(self) -> None:
        for inp in self.inputs:
            inp._check_sanity()

    @no_bool_use_as_property
    def is_null(self):
        return (
            self.unsigned_tx.is_null()
            and not(self.inputs)
            and not(self.outputs)
            and not(self.xpubs)
            and not(self.proprietary_fields)
            and not(self.unknown_fields)
        )

    @classmethod
    def stream_deserialize(cls: Type[T_PartiallySigned_Transaction],
                           f: ByteStream_Type,
                           **kwargs: Any) -> T_PartiallySigned_Transaction:

        magic = ser_read(f, 5)
        if magic != PSBT_MAGIC_HEADER_BYTES:
            raise SerializationError('Invalid PSBT magic bytes')

        proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]] = \
            OrderedDict()
        unknown_fields: List[PSBT_UnknownTypeData] = []
        xpubs: Dict[CCoinExtPubKey, PSBT_KeyDerivationInfo] = OrderedDict()
        unsigned_tx: Optional[CTransaction] = None
        version: int = 0

        keys_seen: Set[bytes] = set()
        for key_type, key_data, value in \
                read_psbt_keymap(f, keys_seen, PSBT_GlobalKeyType,
                                 proprietary_fields, unknown_fields):

            if key_type == PSBT_GlobalKeyType.UNSIGNED_TX:
                ensure_empty_key_data(key_type, key_data)
                unsigned_tx = CTransaction.deserialize(value)
            elif key_type == PSBT_GlobalKeyType.XPUB:
                if key_data[:4] != CCoinExtPubKey.base58_prefix:
                    raise ValueError(
                        f'One of global xpubs has unknown prefix: expected '
                        f'prefix (hex) {b2x(CCoinExtPubKey.base58_prefix)}, '
                        f'got {b2x(key_data[:4])}')
                xpub = CCoinExtPubKey.from_bytes(key_data[4:])
                assert xpub not in xpubs,\
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                xpubs[xpub] = PSBT_KeyDerivationInfo.deserialize(value)
            elif key_type == PSBT_GlobalKeyType.VERSION:
                ensure_empty_key_data(key_type, key_data)
                if len(value) != 4:
                    raise SerializationError(
                        'Incorrect data length for {key_type.name}')
                version = struct.unpack(b'<I', value)[0]
            else:
                raise AssertionError(
                    f'If key type {key_type} is present in PSBT_GLOBAL_KEYS, '
                    f'it must be handled, and this statement '
                    f'should not be reached.')

        if unsigned_tx is None:
            raise ValueError(
                'PSBT does not contain unsigned transaction')

        inputs = []
        for input_index in range(len(unsigned_tx.vin)):
            inputs.append(
                PSBT_Input.stream_deserialize(
                    f, _input_index=input_index, **kwargs))

        outputs = []
        for output_index in range(len(unsigned_tx.vout)):
            outputs.append(
                PSBT_Output.stream_deserialize(
                    f, _output_index=output_index, **kwargs))

        return cls(version=version,
                   inputs=inputs, outputs=outputs,
                   unsigned_tx=unsigned_tx, xpubs=xpubs,
                   proprietary_fields=proprietary_fields,
                   unknown_fields=unknown_fields)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:

        if len(self.unsigned_tx.vin) != len(self.inputs):
            raise AssertionError('inputs length must match unsigned_tx.vin')

        if len(self.unsigned_tx.vout) != len(self.outputs):
            raise AssertionError('outputs length must match unsigned_tx.vout')

        f.write(PSBT_MAGIC_HEADER_BYTES)

        stream_serialize_field(
            PSBT_GlobalKeyType.UNSIGNED_TX, f,
            value=self.unsigned_tx.serialize(include_witness=False))

        if self.version:
            stream_serialize_field(
                PSBT_GlobalKeyType.VERSION, f,
                value=struct.pack(b"<I", self.version))

        for xpub, derinfo in self.xpubs.items():
            stream_serialize_field(
                PSBT_GlobalKeyType.XPUB, f,
                key_data=xpub.base58_prefix + xpub,
                value=PSBT_KeyDerivationInfo.serialize(derinfo))

        stream_serialize_proprietary_fields(self.proprietary_fields, f)
        stream_serialize_unknown_fields(self.unknown_fields, f)

        f.write(PSBT_SEPARATOR)

        for inp in self.inputs:
            inp.stream_serialize(f)

        for outp in self.outputs:
            outp.stream_serialize(f)

    def __repr__(self) -> str:
        xpubs = (
            ', '.join(
                f"'{k}': (x('{b2x(v.fingerprint)}'), \"{str(v.path)}\")"
                for k, v in self.xpubs.items()))

        return (
            f"{self.__class__.__name__}("
            f"version={self.version}, "
            f"inputs={self.inputs}, "
            f"outputs={self.outputs}, "
            f"unsigned_tx={self.unsigned_tx}, "
            f"xpubs={{{xpubs}}}, "
            f"proprietary_fields="
            f"{{{proprietary_field_repr(self.proprietary_fields)}}}, "
            f"unknown_fields=[{unknown_fields_repr(self.unknown_fields)}]"
            f")"
        )


__all__ = (
    'PartiallySignedTransaction',
    'PSBT_Input',
    'PSBT_Output',
    'PSBT_KeyDerivationInfo',
    'PSBT_ProprietaryTypeData',
    'PSBT_UnknownTypeData',
)
