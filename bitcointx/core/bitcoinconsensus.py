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

"""
Use libbitcoinconsensus library
(https://github.com/bitcoin/bitcoin/blob/master/doc/shared-libraries.md)
to evaluate bitcoin script.

"""

import ctypes
from typing import Union, Tuple, Set, Optional

from bitcointx.util import ensure_isinstance
from bitcointx.core import MoneyRange, CTransaction
from bitcointx.core.script import CScript, CScriptWitness
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_NULLDUMMY, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_WITNESS,
    ALL_SCRIPT_VERIFY_FLAGS, ScriptVerifyFlag_Type,
    VerifyScriptError, script_verify_flags_to_string
)

_libbitcoin_consensus = None

BITCOINCONSENSUS_API_VER = 1

# typedef enum bitcoinconsensus_error_t
bitcoinconsensus_ERR_OK = 0
bitcoinconsensus_ERR_TX_INDEX = 1
bitcoinconsensus_ERR_TX_SIZE_MISMATCH = 2
bitcoinconsensus_ERR_TX_DESERIALIZE = 3
bitcoinconsensus_ERR_AMOUNT_REQUIRED = 4
bitcoinconsensus_ERR_INVALID_FLAGS = 5

BITCOINCONENSUS_LAST_ERROR_VALUE = bitcoinconsensus_ERR_INVALID_FLAGS
BITCOINCONSENSUS_ERROR_NAMES = {
    bitcoinconsensus_ERR_OK: 'success',
    bitcoinconsensus_ERR_TX_INDEX: 'input index too large',
    bitcoinconsensus_ERR_TX_SIZE_MISMATCH: 'transaction size mismatch',
    bitcoinconsensus_ERR_TX_DESERIALIZE: 'error deserializing transaction',
    bitcoinconsensus_ERR_AMOUNT_REQUIRED: 'amount required',
    bitcoinconsensus_ERR_INVALID_FLAGS: 'invalid flags supplied'
}

# Script verification flags
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NONE = 0,
# evaluate P2SH (BIP16) subscripts
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH = 1 << 0
# enforce strict DER (BIP66) compliance
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG = 1 << 2
# enforce NULLDUMMY (BIP147)
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY = 1 << 4
# enable CHECKLOCKTIMEVERIFY (BIP65)
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
# enable CHECKSEQUENCEVERIFY (BIP112)
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10
# enable WITNESS (BIP141)
bitcoinconsensus_SCRIPT_FLAGS_VERIFY_WITNESS = 1 << 11

bitcoinconsensus_SCRIPT_FLAGS_VERIFY_ALL = (
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH | bitcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG |
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY | bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | bitcoinconsensus_SCRIPT_FLAGS_VERIFY_WITNESS
)

BITCOINCONSENSUS_FLAG_MAPPING = {
    SCRIPT_VERIFY_P2SH: bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH,
    SCRIPT_VERIFY_DERSIG: bitcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG,
    SCRIPT_VERIFY_NULLDUMMY: bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_WITNESS: bitcoinconsensus_SCRIPT_FLAGS_VERIFY_WITNESS
}

BITCOINCONSENSUS_ACCEPTED_FLAGS = set(BITCOINCONSENSUS_FLAG_MAPPING.keys())


def _flags_to_libconsensus(flags: Union[Tuple[ScriptVerifyFlag_Type, ...],
                                        Set[ScriptVerifyFlag_Type]]
                           ) -> int:
    if isinstance(flags, tuple):
        flags = set(flags)
    elif not isinstance(flags, set):
        raise TypeError('flags must be supplied as a tuple or a set')
    if (flags - ALL_SCRIPT_VERIFY_FLAGS):
        raise ValueError('unknown flags supplied')
    if (flags - BITCOINCONSENSUS_ACCEPTED_FLAGS):
        raise ValueError(
            'some of the supplied flags are not handled '
            'by bitcoinconsensus libary: {}'
            .format(
                script_verify_flags_to_string(
                    flags - BITCOINCONSENSUS_ACCEPTED_FLAGS)))

    flags_value = 0
    for f in flags:
        flags_value |= BITCOINCONSENSUS_FLAG_MAPPING[f]

    return flags_value


def _add_function_definitions(handle: ctypes.CDLL) -> None:

    # Returns 1 if the input nIn of the serialized transaction pointed to by
    # txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
    # the additional constraints specified by flags.
    # If not nullptr, err will contain an error/success code for the operation
    handle.bitcoinconsensus_verify_script_with_amount.restype = ctypes.c_int
    handle.bitcoinconsensus_verify_script_with_amount.argtypes = [
        ctypes.c_char_p,  # const unsigned char *scriptPubKey
        ctypes.c_uint,  # unsigned int scriptPubKeyLen
        ctypes.c_int64,  # int64_t amount
        ctypes.c_char_p,  # const unsigned char *txTo
        ctypes.c_uint,  # unsigned int txToLen
        ctypes.c_uint,  # unsigned int nIn
        ctypes.c_uint,  # unsigned int flags
        ctypes.POINTER(ctypes.c_uint)  # bitcoinconsensus_error* err
    ]

    handle.bitcoinconsensus_version.restype = ctypes.c_int
    handle.bitcoinconsensus_version.argtypes = []


def load_bitcoinconsensus_library(library_name: Optional[str] = None,
                                  path: Optional[str] = None
                                  ) -> ctypes.CDLL:
    """load libsbitcoinconsenssus via ctypes, add default function definitions
    to the library handle, and return this handle.

    The caller is not supposed to use the handle themselves,
    as there are no known functionality at the time of writing
    that is not exposed through ConsensusVerifyScript

    The caller can specify their own name for the library, if they
    want to supply their own `consensus_library_hanlde` to
    `ConsensusVerifyScript()`. In that case, library must be fully
    ABI-compatible with libbitcoinconsensus.

    """
    if path:
        if library_name is not None:
            raise ValueError(
                'Either path or library_name must be supplied, but not both')
    else:
        if library_name is None:
            library_name = 'bitcoinconsensus'

        path = ctypes.util.find_library(library_name)
        if path is None:
            raise ImportError('consensus library not found')

    try:
        handle = ctypes.cdll.LoadLibrary(path)
    except Exception as e:
        raise ImportError('Cannot import consensus library: {}'.format(e))

    _add_function_definitions(handle)

    lib_version = handle.bitcoinconsensus_version()
    if lib_version != BITCOINCONSENSUS_API_VER:
        raise ImportError('bitcoinconsensus_version returned {}, '
                          'while this library only knows how to work with '
                          'version {}'.format(lib_version,
                                              BITCOINCONSENSUS_API_VER))

    return handle


def ConsensusVerifyScript(
    scriptSig: CScript, scriptPubKey: CScript,
    txTo: CTransaction, inIdx: int,
    flags: Union[Tuple[ScriptVerifyFlag_Type, ...],
                 Set[ScriptVerifyFlag_Type]] = (),
    amount: int = 0,
    witness: Optional[CScriptWitness] = None,
    consensus_library_hanlde: Optional[ctypes.CDLL] = None
) -> None:

    """Verify a scriptSig satisfies a scriptPubKey, via libbitcoinconsensus
    `bitcoinconsensus_verify_script_with_amount()` function.

    The arguments are compatible with `VerifyScript()` from
    `bitcointx.core.scripteval`

    scriptSig    - Signature. Must be present in the transaction input at
                   inIdx. Redundant, but is there for compatibility of
                   arguments with VerifyScript() that allow to supply
                   different scriptSig than the one in the input
    scriptPubKey - PubKey
    txTo         - Spending transaction
    inIdx        - Index of the transaction input containing scriptSig
    flags        - Script execution flags (flags defined in
                   `bitcointx.core.scripteval`). Only a subset of flags
                   are allowed (see BITCOINCONSENSUS_ACCEPTED_FLAGS in
                   `bitcointx.core.bitcoinconsensus`)
    amount       - amount of the input
    witness      - CScriptWitness() for the corresponding input.
                   If None, the witness will be taken from the transaction.
                   If not None, the witness in the transaction must be empty,
                   or the same as supplied value.
    consensus_library_hanlde - if supplied, the function
                   `bitcoinconsensus_verify_script_with_amount()` will be
                   called via this handle. If not, default libbitcoinconsensus
                   handle will be used, and the attempt to load the library
                   will be performed on first use.

    Raises a ValidationError subclass if the validation fails.
    May rise ValueError or TypeError if supplied arguments are incorrect.
    May rise RuntimeError if there's some problems with interfaceing with
    the library
    """
    global _libbitcoin_consensus

    if not MoneyRange(amount):
        raise ValueError('amount out of MoneyRange')

    ensure_isinstance(scriptSig, CScript, 'scriptSig')
    if not type(scriptSig) == type(scriptPubKey):
        raise TypeError(
            "scriptSig and scriptPubKey must be of the same script class")

    if txTo.vin[inIdx].scriptSig != scriptSig:
        raise ValueError(
            f'supplied scriptSig is not present in input {inIdx} of '
            f'the supplied transaction')

    if witness is not None:
        ensure_isinstance(witness, CScriptWitness, 'witness')
        if not txTo.wit.vtxinwit[inIdx].scriptWitness.is_null() \
                and txTo.wit.vtxinwit[inIdx].scriptWitness != witness:
            raise ValueError(
                'transaction has witness for input {}, '
                'but it is different from what is supplied as witness kwarg'
                .format(inIdx))
        txTo = txTo.to_mutable()
        txTo.wit.vtxinwit[inIdx].scriptWitness = witness

    handle = consensus_library_hanlde

    if handle is None:
        if _libbitcoin_consensus is None:
            _libbitcoin_consensus = load_bitcoinconsensus_library()
        handle = _libbitcoin_consensus

    tx_data = txTo.serialize()

    libconsensus_flags = _flags_to_libconsensus(flags)

    # bitcoinconsensus_error type is enum, as declared in the C header.
    # enum can be of any size, as chosen by the compiler.
    # most likely it will be of the size of u_int, but there's no guarantee.
    # While teoretically possible, enum is very unlikely to be larger than
    # size of u_int (you do not need billions of enum values, and u_int
    # is just convenient, being the size of the machine word).
    # It conceivable that it may be smaller in size than u_int, though.
    # At least on little-endian architectures, this is not a problem.
    # On big-endian, if the compiler choses u_int8_t for enum, the error
    # that we read afterwards may be wrong. In this case, we will raise
    # RuntimeError.
    error_code = ctypes.c_uint()
    error_code.value = 0

    result = handle.bitcoinconsensus_verify_script_with_amount(
        scriptPubKey, len(scriptPubKey), amount,
        tx_data, len(tx_data), inIdx, libconsensus_flags,
        ctypes.byref(error_code)
    )

    if result == 1:
        # script was verified successfully - just return, no exception raised.
        return

    assert result == 0

    err = error_code.value

    if err > BITCOINCONENSUS_LAST_ERROR_VALUE:
        raise RuntimeError(
            'bitcoinconsensus_verify_script_with_amount failed with '
            'unknown error code {}'.format(err))

    if err != bitcoinconsensus_ERR_OK:
        # The errors returned are all about the input values.
        # Therefore it seems appropriate to raise ValueError here
        raise ValueError(BITCOINCONSENSUS_ERROR_NAMES[err])

    raise VerifyScriptError('script verification failed')


__all__ = (
    'load_bitcoinconsensus_library',
    'ConsensusVerifyScript'
)
