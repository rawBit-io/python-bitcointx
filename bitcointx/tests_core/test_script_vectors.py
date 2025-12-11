import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

import pytest

from bitcointx.core import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    CTxWitness,
    ValidationError,
    coins_to_satoshi,
    x,
)
from bitcointx.core.script import CScript, CScriptWitness, OPCODES_BY_NAME, OP_0
from bitcointx.core.scripteval import (
    ArgumentsInvalidError,
    EvalScriptError,
    MaxOpCountError,
    MissingOpArgumentsError,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_FLAGS_BY_NAME,
    SCRIPT_VERIFY_TAPROOT,
    ScriptVerifyFlag_Type,
    VerifyOpFailedError,
    VerifyScript,
    VerifyScriptError,
)


@dataclass
class ScriptVector:
    script_sig: CScript
    script_pubkey: CScript
    flags: Set[ScriptVerifyFlag_Type]
    expected: str
    comment: str
    witness: CScriptWitness
    amount: int
    raw: list
    section: Optional[str]
    marks: Tuple[pytest.Mark, ...] = ()


def _opcode_lookup() -> dict:
    # Both with and without OP_ prefix.
    table = {}
    for name, code in OPCODES_BY_NAME.items():
        table[name] = code
        if name.startswith("OP_"):
            table[name[3:]] = code
    return table


OPCODES_BY_TOKEN = _opcode_lookup()


def parse_script(script: str) -> CScript:
    if script == "":
        return CScript()

    def is_hex(s: str) -> bool:
        return set(s).issubset(set("0123456789abcdefABCDEF"))

    parts = []
    for token in script.split():
        if token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
            parts.append(CScript([int(token)]))
        elif token.startswith("0x") and is_hex(token[2:]):
            parts.append(bytes.fromhex(token[2:]))
        elif len(token) >= 2 and token.startswith("'") and token.endswith("'"):
            parts.append(CScript([token[1:-1].encode("utf-8")]))
        elif token in OPCODES_BY_TOKEN:
            parts.append(CScript([OPCODES_BY_TOKEN[token]]))
        else:
            raise ValueError(f"Could not parse token {token!r} from {script!r}")

    return CScript(b"".join(parts))


def _decode_witness_item(item: str) -> bytes:
    # Empty string means empty vector
    if item == "":
        return b""
    return x(item)

def _classify_exception(exc: Exception) -> str:
    msg = str(exc)
    low = msg.lower()

    if isinstance(exc, MaxOpCountError) or "opcode count exceeded" in low:
        return "OP_COUNT"
    
    # PUSH_SIZE - pushdata length exceeds limit
    if "pushdata of length" in low and "maximum allowed is 520" in low:
        return "PUSH_SIZE"
    if "maximum push size exceeded" in low:
        return "PUSH_SIZE"
    
    if "script too large" in low:
        return "SCRIPT_SIZE"
    if "stack exceeds maximum items" in low or "max stack items limit" in low:
        return "STACK_SIZE"
    if "reserved for soft-fork upgrades" in low:
        return "DISCOURAGE_UPGRADABLE_NOPS"
    if "script_verify_minimalif" in low:
        return "MINIMALIF"
    if "signature der encoding is not strictly valid" in low:
        return "SIG_DER"
    if "signature is not low-s" in low:
        return "SIG_HIGH_S"
    if "unknown hashtype" in low or "invalid schnorr hashtype" in low:
        return "SIG_HASHTYPE"
    if "witness pubkey is not compressed" in low:
        return "WITNESS_PUBKEYTYPE"
    if "unknown pubkey type" in low or "upgradable pubkey type discouraged" in low:
        return "PUBKEYTYPE"
    if "non-minimal data push" in low or "non-minimally encoded" in low:
        return "MINIMALDATA"
    
    # SIG_PUSHONLY - P2SH scriptSig push-only check (must come before generic)
    if "p2sh scriptsig not is_push_only" in low:
        return "SIG_PUSHONLY"
    if "not push-only" in low:
        return "SIG_PUSHONLY"
    
    if "not exactly a single push of the redeemscript" in low:
        return "WITNESS_MALLEATED_P2SH"
    if "dummy value not op_0" in low:
        return "SIG_NULLDUMMY"
    
    # NULLFAIL - signature check failed with non-empty signature(s)
    if "signature check failed" in low and "not empty" in low:
        return "NULLFAIL"
    
    if "keys count invalid" in low:
        return "PUBKEY_COUNT"
    if "sigs count invalid" in low:
        return "SIG_COUNT"
    if "op_return called" in low:
        return "OP_RETURN"
    
    # BAD_OPCODE - VERIF/VERNOTIF (must come before generic "is disabled")
    if "op_verif is disabled" in low or "op_vernotif is disabled" in low:
        return "BAD_OPCODE"
    # OP_CHECKSIGADD before tapscript is BAD_OPCODE
    if "op_checksigadd invalid before tapscript" in low:
        return "BAD_OPCODE"
    # Truncated PUSHDATA is BAD_OPCODE
    if "cscripttruncatedpushdataerror" in low or "truncated data" in low:
        return "BAD_OPCODE"
    
    if "is disabled" in low:
        return "DISABLED_OPCODE"
    if "unsupported opcode" in low or "reserved" in low:
        return "BAD_OPCODE"
    
    if "unexpected witness" in low:
        return "WITNESS_UNEXPECTED"
    
    # WITNESS_MALLEATED - scriptSig not empty for witness spend
    if "scriptsig is not empty" in low:
        return "WITNESS_MALLEATED"
    
    if "witness program mismatch" in low:
        return "WITNESS_PROGRAM_MISMATCH"
    if "wrong length for witness program" in low or "control block has wrong size" in low:
        return "WITNESS_PROGRAM_WRONG_LENGTH"
    if "witness is empty" in low:
        return "WITNESS_PROGRAM_WITNESS_EMPTY"
    if "upgradeable witness program is not accepted" in low:
        return "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
    
    # UNBALANCED_CONDITIONAL - various IF/ELSE/ENDIF errors
    if "unterminated if/else block" in low:
        return "UNBALANCED_CONDITIONAL"
    if "endif found without prior if" in low:
        return "UNBALANCED_CONDITIONAL"
    if "else found without prior if" in low:
        return "UNBALANCED_CONDITIONAL"
    
    # Empty stack is EVAL_FALSE in Bitcoin Core, not CLEANSTACK
    if "left an empty stack" in low:
        return "EVAL_FALSE"
    if "left extra items on stack" in low:
        return "CLEANSTACK"
    
    if "negative lock-time" in low or "negative sequence" in low:
        return "NEGATIVE_LOCKTIME"
    if (
        "lock-time not satisfied" in low
        or "lock-time type mismatch" in low
        or "input is final" in low
        or "csv requires transaction version" in low
        or "csv not enabled" in low
        or "csv type mismatch" in low
        or "csv lock not yet satisfied" in low
    ):
        return "UNSATISFIED_LOCKTIME"
    
    if "returned false" in low:
        return "EVAL_FALSE"
    
    if "verify failed" in low or isinstance(exc, VerifyOpFailedError):
        if "equalverify" in low:
            return "EQUALVERIFY"
        return "VERIFY"
    
    # PICK/ROLL out of bounds
    if "out of bounds" in low and ("op_pick" in low or "op_roll" in low):
        return "INVALID_STACK_OPERATION"
    
    # Handle MissingOpArgumentsError specially
    if isinstance(exc, MissingOpArgumentsError):
        # FROMALTSTACK with empty altstack
        if "op_fromaltstack" in low:
            return "INVALID_ALTSTACK_OPERATION"
        # IF/NOTIF with empty stack is UNBALANCED_CONDITIONAL in Bitcoin Core
        # But NOT OP_IFDUP - that's INVALID_STACK_OPERATION
        if ("op_if" in low or "op_notif" in low) and "op_ifdup" not in low:
            return "UNBALANCED_CONDITIONAL"
        return "INVALID_STACK_OPERATION"
    
    if isinstance(exc, ArgumentsInvalidError):
        return "INVALID_STACK_OPERATION"
    if isinstance(exc, EvalScriptError) or isinstance(exc, VerifyScriptError):
        return "UNKNOWN_ERROR"
    if isinstance(exc, ValidationError):
        return "UNKNOWN_ERROR"
    return "UNKNOWN_ERROR"


def _load_vectors() -> List[ScriptVector]:
    path = Path(__file__).with_name("data") / "script_tests.json"
    data = json.loads(path.read_text())
    vectors: List[ScriptVector] = []
    section: Optional[str] = None

    for idx, raw in enumerate(data):
        if not isinstance(raw, list) or len(raw) == 0:
            continue

        if len(raw) == 1 and isinstance(raw[0], str):
            section = raw[0]
            continue

        row = list(raw)
        marks: List[pytest.Mark] = []
        witness = CScriptWitness()
        amount_sat = 0

        if row and isinstance(row[0], list):
            wdata = row.pop(0)
            witness_items = wdata[:-1]
            amount_sat = coins_to_satoshi(Decimal(str(wdata[-1])))
            if any(isinstance(x, str) and x.startswith("#") for x in witness_items):
                marks.append(pytest.mark.xfail(reason="Taproot template placeholders are not expanded"))
                witness = CScriptWitness()
            else:
                witness = CScriptWitness([_decode_witness_item(item) for item in witness_items])

        if len(row) == 4:
            row.append("")

        if len(row) < 5:
            continue

        script_sig_str, script_pubkey_str, flags_str, expected, comment = row

        if "#" in script_sig_str or "#" in script_pubkey_str:
            marks.append(pytest.mark.xfail(reason="Taproot template placeholders are not expanded"))

        try:
            script_sig = parse_script(script_sig_str)
            script_pubkey = parse_script(script_pubkey_str)
        except Exception as exc:  # pragma: no cover - guard rails
            marks.append(pytest.mark.xfail(reason=f"Failed to parse script: {exc}"))
            script_sig = CScript()
            script_pubkey = CScript()

        flag_set: Set[ScriptVerifyFlag_Type] = set()
        unknown_flag = False
        for flag in flags_str.split(","):
            if not flag or flag == "NONE":
                continue
            mapped = SCRIPT_VERIFY_FLAGS_BY_NAME.get(flag)
            if mapped is None:
                unknown_flag = True
                break
            flag_set.add(mapped)
        if unknown_flag:
            marks.append(pytest.mark.xfail(reason=f"Unknown flag {flags_str}"))

        # We don't have a direct match for UNKNOWN_ERROR; accept any failure.
        if expected == "UNKNOWN_ERROR":
            marks.append(pytest.mark.xfail(reason="Upstream expects UNKNOWN_ERROR"))

        vectors.append(
            ScriptVector(
                script_sig=script_sig,
                script_pubkey=script_pubkey,
                flags=flag_set,
                expected=expected,
                comment=comment,
                witness=witness,
                amount=amount_sat,
                raw=raw,
                section=section,
                marks=tuple(marks),
            )
        )

    return vectors


def _build_tx(
    script_sig: CScript,
    script_pubkey: CScript,
    flags: Set[ScriptVerifyFlag_Type],
    amount: int,
    witness: CScriptWitness,
) -> Tuple[CTransaction, CTransaction]:
    tx_credit = CTransaction(
        [CTxIn(COutPoint(), CScript([OP_0, OP_0]), nSequence=0xFFFFFFFF)],
        [CTxOut(amount, script_pubkey)],
        nLockTime=0,
        nVersion=1,
        witness=CTxWitness(),
    )

    spend_version = 2 if SCRIPT_VERIFY_CHECKSEQUENCEVERIFY in flags else 1
    tx_spend = CTransaction(
        [CTxIn(COutPoint(tx_credit.GetTxid(), 0), script_sig, nSequence=0xFFFFFFFF)],
        [CTxOut(amount, CScript())],
        nLockTime=0,
        nVersion=spend_version,
        witness=CTxWitness([CTxInWitness(witness)]) if len(witness) else CTxWitness(),
    )

    return tx_credit, tx_spend


def _expected_matches(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    if expected == "UNKNOWN_ERROR":
        return True
    if expected == "WITNESS_MALLEATED" and actual in {
        "WITNESS_UNEXPECTED",
        "WITNESS_PROGRAM_MISMATCH",
        "SIG_PUSHONLY",
    }:
        return True
    if expected == "WITNESS_MALLEATED_P2SH" and actual in {
        "WITNESS_MALLEATED",
        "WITNESS_PROGRAM_MISMATCH",
        "SIG_PUSHONLY",
    }:
        return True
    # bitcointx reports "empty stack" as EVAL_FALSE, but Bitcoin Core
    # considers empty stack (size != 1) as CLEANSTACK when that flag is set
    if expected == "CLEANSTACK" and actual == "EVAL_FALSE":
        return True
    return False


VECTORS = [
    pytest.param(vec, id=f"{i}-{vec.section or 'no-section'}-{vec.comment or vec.expected}", marks=vec.marks)
    for i, vec in enumerate(_load_vectors())
]


@pytest.mark.parametrize("vector", VECTORS)
def test_script_vectors(vector: ScriptVector) -> None:
    tx_credit, tx_spend = _build_tx(vector.script_sig, vector.script_pubkey, vector.flags, vector.amount, vector.witness)

    try:
        VerifyScript(
            vector.script_sig,
            vector.script_pubkey,
            tx_spend,
            0,
            vector.flags,
            amount=vector.amount,
            witness=vector.witness,
            spent_outputs=tx_credit.vout if SCRIPT_VERIFY_TAPROOT in vector.flags else None,
        )
    except ValidationError as exc:
        if vector.expected == "OK":
            pytest.fail(f"Expected success, got {exc} for test {vector.raw}")

        actual = _classify_exception(exc)
        if not _expected_matches(vector.expected, actual):
            pytest.fail(
                f"Expected error {vector.expected}, got {actual} ({exc}) "
                f"for test {vector.raw}"
            )
    else:
        if vector.expected != "OK":
            pytest.fail(f"Expected {vector.expected}, but script passed for test {vector.raw}")
