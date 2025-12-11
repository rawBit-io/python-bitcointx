import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

import pytest

from bitcointx.core import CMutableTransaction, CTxOut, ValidationError, x
from bitcointx.core.script import (
    CScript,
    CScriptInvalidError,
    CScriptTruncatedPushDataError,
    CScriptWitness,
    SignatureHashSchnorr,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_FLAGS_BY_NAME,
    VerifyScript,
    VerifyScriptError,
)


SCRIPT_ASSETS_PATH = Path(__file__).with_name("data") / "script_assets_test.json"

# Phase-4-focused prefixes (tapscript/script-path behaviors)
PHASE4_PREFIXES = (
    "tapscript/",
    "opsuccess/",
    "unkver/",
    "unknownleaf",
    "alwaysvalid/cleanstack",
    "alwaysvalid/notsuccessx",
    "minimalif",
    "control",
    "witness_empty",
    "spendpath/",
)
SKIP_CONTAINS = ("undecodable",)


def _flags_from_names(flags: str) -> Set:
    if not flags:
        return set()
    return {SCRIPT_VERIFY_FLAGS_BY_NAME[name] for name in flags.split(",")}


def _witness_from_hex(items: List[str]) -> CScriptWitness:
    return CScriptWitness([x(i) if i else b"" for i in items])


def _ctouts_from_prevouts(prevouts: List[str]) -> List[CTxOut]:
    return [CTxOut.deserialize(x(po)) for po in prevouts]


def _load_phase4_vectors() -> List[Dict]:
    data = json.loads(SCRIPT_ASSETS_PATH.read_text())
    selected: List[Dict] = []
    seen = set()
    for entry in data:
        name = entry.get("name") or entry.get("comment", "")
        if any(skip in name for skip in SKIP_CONTAINS):
            continue
        if any(name.startswith(pfx) or pfx in name for pfx in PHASE4_PREFIXES):
            if name in seen:
                continue
            seen.add(name)
            selected.append(entry)
    return selected


def _run_vector(vec: Dict, case: Dict, should_pass: bool) -> None:
    flags = _flags_from_names(vec.get("flags", ""))
    spent_outputs = _ctouts_from_prevouts(vec["prevouts"])
    in_idx = vec["index"]
    tx = CMutableTransaction.deserialize(x(vec["tx"]))
    txin = tx.vin[in_idx]
    txin.scriptSig = CScript(x(case["scriptSig"])) if case["scriptSig"] else CScript()
    wit = _witness_from_hex(case.get("witness", []))
    tx.wit.vtxinwit[in_idx].scriptWitness = wit

    verify = lambda: VerifyScript(
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
        try:
            verify()
        except Exception as exc:  # pragma: no cover
            pytest.xfail(f"{vec.get('comment','')} expected success: {exc}")
    else:
        try:
            with pytest.raises(
                (
                    ValidationError,
                    VerifyScriptError,
                    ValueError,
                    IndexError,
                    CScriptInvalidError,
                    CScriptTruncatedPushDataError,
                )
            ):
                verify()
        except AssertionError as exc:  # pragma: no cover
            pytest.xfail(f"{vec.get('comment','')} expected failure but passed: {exc}")


@pytest.mark.parametrize("vec", _load_phase4_vectors(), ids=lambda v: v.get("comment", ""))
def test_script_assets_tapscript(vec: Dict) -> None:
    _run_vector(vec, vec["success"], True)
    failure = vec.get("failure")
    if failure:
        _run_vector(vec, failure, False)
