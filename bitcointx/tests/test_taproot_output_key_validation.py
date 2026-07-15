# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

from typing import Tuple

import pytest

from bitcointx.core import COutPoint, CTransaction, CTxIn, CTxOut
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OP_1,
    TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    VerifyScript,
    VerifyScriptError,
    VerifyScriptWithTrace,
)
from bitcointx.wallet import CCoinKey


AMOUNT = 100_000
TAPROOT_FLAGS = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
}
TAPROOT_KEY = CCoinKey.from_secret_bytes((2).to_bytes(32, "big"))


def _off_curve_taproot_scriptpath_spend(
) -> Tuple[CScript, CScriptWitness, CTransaction, Tuple[CTxOut, ...]]:
    leaf_name = "valid-leaf"
    leaf = CScript([OP_1], name=leaf_name)
    tree = TaprootScriptTree([leaf], internal_pubkey=TAPROOT_KEY.xonly_pub)
    script_and_control = tree.get_script_with_control_block(leaf_name)
    assert script_and_control is not None
    committed_leaf, control = script_and_control

    script_pubkey = CScript([OP_1, b"\xff" * 32])
    witness = CScriptWitness([committed_leaf, control])
    spend = CTransaction(
        [CTxIn(COutPoint(b"\x22" * 32, 0), CScript(), 0xFFFFFFFE)],
        [],
    )
    spent_outputs = (CTxOut(AMOUNT, script_pubkey),)
    return script_pubkey, witness, spend, spent_outputs


def test_off_curve_taproot_output_key_is_a_validation_error() -> None:
    script_pubkey, witness, spend, spent_outputs = (
        _off_curve_taproot_scriptpath_spend()
    )

    with pytest.raises(
        VerifyScriptError, match="^witness program mismatch$"
    ) as exc_info:
        VerifyScript(
            CScript(),
            script_pubkey,
            spend,
            0,
            flags=TAPROOT_FLAGS,
            amount=AMOUNT,
            witness=witness,
            spent_outputs=spent_outputs,
        )
    assert type(exc_info.value) is VerifyScriptError

    ok, _, error = VerifyScriptWithTrace(
        CScript(),
        script_pubkey,
        spend,
        0,
        flags=TAPROOT_FLAGS,
        amount=AMOUNT,
        witness=witness,
        spent_outputs=spent_outputs,
    )
    assert ok is False
    assert error == "witness program mismatch"
