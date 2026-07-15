# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

from typing import List, Tuple

import pytest

from bitcointx.core import COutPoint, CTransaction, CTxIn, CTxOut
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    ScriptElement_Type,
    OP_0,
    OP_1,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CODESEPARATOR,
    OP_DROP,
    OP_ENDIF,
    OP_IF,
    SIGHASH_ALL,
    SIGVERSION_BASE,
    SIGVERSION_WITNESS_V0,
)
from bitcointx.core.scripteval import (
    EvalScript,
    EvalScriptError,
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    STANDARD_SCRIPT_VERIFY_FLAGS,
    UNHANDLED_SCRIPT_VERIFY_FLAGS,
    VerifyScript,
)


_KEY = CKey.from_secret_bytes((7).to_bytes(32, "big"))
_TX = CTransaction(
    [CTxIn(COutPoint(b"\x11" * 32, 0), CScript(), 0xFFFFFFFF)],
    [CTxOut(1, CScript([OP_1]))],
)


def _signature_find_and_delete_vector(
    *, multisig: bool, verify: bool
) -> Tuple[CScript, CScript]:
    if multisig:
        opcode = OP_CHECKMULTISIGVERIFY if verify else OP_CHECKMULTISIG
        suffix_parts: List[ScriptElement_Type] = [
            OP_DROP, OP_1, _KEY.pub, OP_1, opcode
        ]
    else:
        opcode = OP_CHECKSIGVERIFY if verify else OP_CHECKSIG
        suffix_parts = [OP_DROP, _KEY.pub, opcode]
    if verify:
        suffix_parts.append(OP_1)
    suffix = CScript(suffix_parts)

    sighash = suffix.sighash(
        _TX, 0, SIGHASH_ALL, sigversion=SIGVERSION_BASE
    )
    signature = _KEY.sign(sighash) + bytes([SIGHASH_ALL])

    # The extra signature push is executed and dropped before the signature
    # opcode. Legacy FindAndDelete removes that same push from scriptCode.
    script_pubkey = CScript(
        bytes(CScript([signature])) + bytes(suffix)
    )
    if multisig:
        script_sig = CScript([b"", signature])
    else:
        script_sig = CScript([signature])

    return script_sig, script_pubkey


@pytest.mark.parametrize(
    "script_pubkey",
    [
        CScript([OP_CODESEPARATOR, OP_1]),
        CScript([OP_0, OP_IF, OP_CODESEPARATOR, OP_ENDIF, OP_1]),
    ],
    ids=["active", "inactive-branch"],
)
def test_const_scriptcode_rejects_base_codeseparator_before_execution(
    script_pubkey: CScript,
) -> None:
    VerifyScript(CScript(), script_pubkey, _TX, 0, flags=set())

    with pytest.raises(
        EvalScriptError,
        match="Using OP_CODESEPARATOR in non-witness script",
    ):
        VerifyScript(
            CScript(),
            script_pubkey,
            _TX,
            0,
            flags={SCRIPT_VERIFY_CONST_SCRIPTCODE},
        )


def test_const_scriptcode_allows_witness_v0_codeseparator() -> None:
    stack: List[bytes] = []
    EvalScript(
        stack,
        CScript([OP_CODESEPARATOR, OP_1]),
        _TX,
        0,
        flags={SCRIPT_VERIFY_CONST_SCRIPTCODE},
        sigversion=SIGVERSION_WITNESS_V0,
    )
    assert stack == [b"\x01"]


@pytest.mark.parametrize(
    ("multisig", "verify"),
    [
        (False, False),
        (False, True),
        (True, False),
        (True, True),
    ],
    ids=[
        "checksig",
        "checksigverify",
        "checkmultisig",
        "checkmultisigverify",
    ],
)
def test_const_scriptcode_rejects_signature_find_and_delete(
    multisig: bool, verify: bool
) -> None:
    script_sig, script_pubkey = _signature_find_and_delete_vector(
        multisig=multisig, verify=verify
    )

    VerifyScript(script_sig, script_pubkey, _TX, 0, flags=set())

    with pytest.raises(
        EvalScriptError, match="Signature is found in scriptCode"
    ):
        VerifyScript(
            script_sig,
            script_pubkey,
            _TX,
            0,
            flags={SCRIPT_VERIFY_CONST_SCRIPTCODE},
        )


def test_const_scriptcode_is_supported_and_active_by_default() -> None:
    assert SCRIPT_VERIFY_CONST_SCRIPTCODE not in UNHANDLED_SCRIPT_VERIFY_FLAGS
    assert SCRIPT_VERIFY_CONST_SCRIPTCODE in (
        STANDARD_SCRIPT_VERIFY_FLAGS - UNHANDLED_SCRIPT_VERIFY_FLAGS
    )


def test_const_scriptcode_default_flags_reject_base_codeseparator() -> None:
    with pytest.raises(
        EvalScriptError,
        match="Using OP_CODESEPARATOR in non-witness script",
    ):
        VerifyScript(
            CScript(), CScript([OP_CODESEPARATOR, OP_1]), _TX, 0
        )


def test_const_scriptcode_witness_entrypoint_control() -> None:
    witness_script = CScript([OP_CODESEPARATOR, OP_1])
    script_pubkey = witness_script.to_p2wsh_scriptPubKey()
    VerifyScript(
        CScript(),
        script_pubkey,
        _TX,
        0,
        flags={
            SCRIPT_VERIFY_P2SH,
            SCRIPT_VERIFY_WITNESS,
            SCRIPT_VERIFY_CONST_SCRIPTCODE,
        },
        witness=CScriptWitness([witness_script]),
    )
