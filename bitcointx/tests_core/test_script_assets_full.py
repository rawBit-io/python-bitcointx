# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

"""Full-corpus gate over Bitcoin Core's script_assets_test.json.

The phase-scoped harnesses (test_taproot_keypath / test_taproot_scriptpath /
test_tapscript_budget) select vectors by comment prefix, which leaves most of
the corpus unexercised as a committed gate. This module runs EVERY entry —
each success case must verify, each failure case must be rejected. The whole
sweep costs a few seconds, so it runs per push, not nightly.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Set

import pytest

from bitcointx.core import CMutableTransaction, CTxOut, ValidationError, x
from bitcointx.core.script import CScript, CScriptWitness
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_FLAGS_BY_NAME,
    ScriptVerifyFlag_Type,
    VerifyScript,
)

JsonObject = Dict[str, Any]


def _load_all_script_asset_vectors() -> List[JsonObject]:
    path = Path(__file__).with_name("data") / "script_assets_test.json"
    data: List[JsonObject] = json.loads(path.read_text())
    return data


def _flags_from_names(flags: str) -> Set[ScriptVerifyFlag_Type]:
    if not flags:
        return set()
    return {SCRIPT_VERIFY_FLAGS_BY_NAME[name] for name in flags.split(",")}


def _witness_from_hex(items: List[str]) -> CScriptWitness:
    return CScriptWitness([x(i) if i else b"" for i in items])


def _ctouts_from_prevouts(prevouts: List[str]) -> List[CTxOut]:
    return [CTxOut.deserialize(x(po)) for po in prevouts]


def _vector_id(vec: JsonObject) -> str:
    return str(vec.get("comment", "no-comment"))


@pytest.mark.parametrize(
    "vec", _load_all_script_asset_vectors(), ids=_vector_id
)
def test_script_assets_full_corpus(vec: JsonObject) -> None:
    flags = _flags_from_names(vec.get("flags", ""))
    spent_outputs = _ctouts_from_prevouts(vec["prevouts"])
    in_idx = vec["index"]
    tx_hex = vec["tx"]

    def run_case(case: JsonObject, should_pass: bool) -> None:
        tx = CMutableTransaction.deserialize(x(tx_hex))
        txin = tx.vin[in_idx]
        txin.scriptSig = (
            CScript(x(case["scriptSig"])) if case["scriptSig"] else CScript()
        )
        wit = _witness_from_hex(case.get("witness", []))
        tx.wit.vtxinwit[in_idx].scriptWitness = wit

        def verify() -> None:
            VerifyScript(
                txin.scriptSig,
                spent_outputs[in_idx].scriptPubKey,
                tx,
                in_idx,
                flags=flags,
                amount=spent_outputs[in_idx].nValue,
                witness=wit,
                spent_outputs=spent_outputs,
            )

        if should_pass:
            verify()
        else:
            # Deliberately narrow: every failure vector must reject with a
            # ValidationError subclass. A bare ValueError/IndexError out of
            # the engine is an internal bug, not a rejection.
            with pytest.raises(ValidationError):
                verify()

    run_case(vec["success"], True)
    failure_case = vec.get("failure")
    if failure_case:
        run_case(failure_case, False)
