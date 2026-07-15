from typing import Tuple

import pytest

from bitcointx.core import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    ValidationError,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OP_0,
    OP_1,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CODESEPARATOR,
    OP_DROP,
    OP_ENDIF,
    OP_IF,
    SIGHASH_ALL,
    SIGVERSION_TAPSCRIPT,
    SIGVERSION_WITNESS_V0,
    TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    EvalScript,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    VerifyScript,
)
from bitcointx.wallet import CCoinKey, P2TRCoinAddress


AMOUNT = 100_000
SEGWIT_FLAGS = {SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS}
TAPROOT_FLAGS = SEGWIT_FLAGS | {SCRIPT_VERIFY_TAPROOT}
ECDSA_KEY = CKey.from_secret_bytes((1).to_bytes(32, "big"))
TAPROOT_KEY = CCoinKey.from_secret_bytes((2).to_bytes(32, "big"))


def _concat_scripts(*parts: CScript) -> CScript:
    return CScript(b"".join(bytes(part) for part in parts))


def _p2wsh_spend(witness_script: CScript) -> Tuple[CScript, CTransaction]:
    script_pubkey = witness_script.to_p2wsh_scriptPubKey()
    credit = CTransaction(
        [CTxIn(COutPoint(), CScript(), 0xFFFFFFFF)],
        [CTxOut(AMOUNT, script_pubkey)],
    )
    spend = CTransaction(
        [CTxIn(COutPoint(credit.GetTxid(), 0), CScript(), 0xFFFFFFFE)],
        [CTxOut(AMOUNT - 1_000, CScript([OP_1]))],
    )
    return script_pubkey, spend


def _bip143_signature(script_code: CScript, spend: CTransaction) -> bytes:
    sighash = script_code.sighash(
        spend,
        0,
        SIGHASH_ALL,
        amount=AMOUNT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    return ECDSA_KEY.sign(sighash) + bytes([SIGHASH_ALL])


def _verify_p2wsh_signature(
    witness_script: CScript,
    script_pubkey: CScript,
    spend: CTransaction,
    signature: bytes,
    *,
    multisig: bool = False,
    amount: int = AMOUNT,
) -> None:
    witness_items = ([b"", signature] if multisig else [signature])
    witness = CScriptWitness(witness_items + [witness_script])
    VerifyScript(
        CScript(),
        script_pubkey,
        spend,
        0,
        flags=SEGWIT_FLAGS,
        amount=amount,
        witness=witness,
        spent_outputs=[],
    )


def test_bip143_core_and_codesep_inclusive_signature_pair() -> None:
    spend = CTransaction.deserialize(bytes.fromhex(
        "0200000001222222222222222222222222222222222222222222222222222222"
        "22222222220300000000feffffff01282300000000000001512a000000"
    ))
    witness_script = CScript(bytes.fromhex(
        "ab21034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b7040"
        "75871aaac"
    ))
    script_pubkey = witness_script.to_p2wsh_scriptPubKey()
    core_signature = bytes.fromhex(
        "30440220282e7073ffb1f939fe9b674ebaca1b5945c862ba03cec16b5e851139"
        "bab7a9310220168fab105c3edc4cfaac613549885328fe0b55fe3dbc4539ee5c"
        "b6d26e6fc0da01"
    )
    codesep_inclusive_signature = bytes.fromhex(
        "30440220791a22a552ce62972ea5b495499506b3d07668e6d3628831e2263256"
        "92d9551002206bd0f7b7e12b9aff261f4b65950a9a562814b5dca0636ceecba6"
        "01b0bb1758ab01"
    )

    _verify_p2wsh_signature(
        witness_script, script_pubkey, spend, core_signature, amount=10_000
    )
    with pytest.raises(ValidationError):
        _verify_p2wsh_signature(
            witness_script,
            script_pubkey,
            spend,
            codesep_inclusive_signature,
            amount=10_000,
        )


@pytest.mark.parametrize("multisig", [False, True], ids=["checksig", "checkmultisig"])
def test_bip143_executed_codeseparator_uses_following_script(multisig: bool) -> None:
    if multisig:
        suffix = CScript([OP_1, ECDSA_KEY.pub, OP_1, OP_CHECKMULTISIG])
    else:
        suffix = CScript([ECDSA_KEY.pub, OP_CHECKSIG])
    witness_script = _concat_scripts(CScript([OP_CODESEPARATOR]), suffix)
    script_pubkey, spend = _p2wsh_spend(witness_script)

    core_signature = _bip143_signature(suffix, spend)
    _verify_p2wsh_signature(
        witness_script,
        script_pubkey,
        spend,
        core_signature,
        multisig=multisig,
    )

    codesep_inclusive_signature = _bip143_signature(witness_script, spend)
    with pytest.raises(ValidationError):
        _verify_p2wsh_signature(
            witness_script,
            script_pubkey,
            spend,
            codesep_inclusive_signature,
            multisig=multisig,
        )


def test_bip143_multiple_codeseparators_use_only_the_last_executed_one() -> None:
    suffix = CScript([ECDSA_KEY.pub, OP_CHECKSIG])
    after_first_separator = _concat_scripts(
        CScript([OP_CODESEPARATOR]), suffix
    )
    witness_script = _concat_scripts(
        CScript([OP_CODESEPARATOR]), after_first_separator
    )
    script_pubkey, spend = _p2wsh_spend(witness_script)

    _verify_p2wsh_signature(
        witness_script,
        script_pubkey,
        spend,
        _bip143_signature(suffix, spend),
    )
    with pytest.raises(ValidationError):
        _verify_p2wsh_signature(
            witness_script,
            script_pubkey,
            spend,
            _bip143_signature(after_first_separator, spend),
        )


def test_bip143_codeseparator_in_unexecuted_branch_does_not_change_scriptcode() -> None:
    suffix = CScript([ECDSA_KEY.pub, OP_CHECKSIG])
    witness_script = _concat_scripts(
        CScript([OP_0, OP_IF, OP_CODESEPARATOR, OP_ENDIF]), suffix
    )
    script_pubkey, spend = _p2wsh_spend(witness_script)

    _verify_p2wsh_signature(
        witness_script,
        script_pubkey,
        spend,
        _bip143_signature(witness_script, spend),
    )
    wrongly_sliced_scriptcode = _concat_scripts(CScript([OP_ENDIF]), suffix)
    with pytest.raises(ValidationError):
        _verify_p2wsh_signature(
            witness_script,
            script_pubkey,
            spend,
            _bip143_signature(wrongly_sliced_scriptcode, spend),
        )


@pytest.mark.parametrize(
    "sigversion", [SIGVERSION_WITNESS_V0, SIGVERSION_TAPSCRIPT]
)
def test_csv_treats_transaction_version_as_unsigned(sigversion: int) -> None:
    tx = CTransaction(
        [CTxIn(COutPoint(), CScript(), 0)],
        [CTxOut(1, CScript([OP_1]))],
        nVersion=-1,
    )
    stack = []
    EvalScript(
        stack,
        CScript([OP_0, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1]),
        tx,
        0,
        flags={SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
        sigversion=sigversion,
    )
    assert stack == [b"\x01"]


@pytest.mark.parametrize(
    ("lock_time", "expected"),
    [
        (0, "97c1e7dfec99d11acf5711cbe8d6c3251dbf1b8456f9b0f73f0edfbddd889751"),
        (0x7FFFFFFF, "b36373ce4566c6277d76d845b43b0da2c08a56378a7799e5150bb38db68cf213"),
        (0x80000000, "cd97087e2514615486dbc428b596f1121da4fe5d0a7f6fed4a9e6d855b1f0450"),
        (0xFFFFFFFF, "326d7a23a4f838e9fbb95e8f9f9c3806b216ee6da363ea6e8bd45bbb4e12a7c5"),
    ],
)
def test_bip143_locktime_boundaries(lock_time: int, expected: str) -> None:
    tx = CTransaction(
        [CTxIn(COutPoint(b"\x11" * 32, 2), CScript(), 0xABCDEF01)],
        [CTxOut(123_456_789, CScript([OP_1]))],
        nVersion=2,
        nLockTime=lock_time,
    )
    sighash = CScript([OP_1]).sighash(
        tx,
        0,
        SIGHASH_ALL,
        amount=5_000_000_000,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    assert sighash.hex() == expected


def _taproot_scriptpath_spend(
    script: CScript,
) -> Tuple[CScript, bytes, CScript, CTransaction, Tuple[CTxOut, ...]]:
    tree = TaprootScriptTree([script], internal_pubkey=TAPROOT_KEY.xonly_pub)
    script_and_control = tree.get_script_with_control_block(script.name)
    assert script_and_control is not None
    leaf_script, control = script_and_control
    script_pubkey = P2TRCoinAddress.from_script_tree(tree).to_scriptPubKey()
    spent_outputs = (CTxOut(AMOUNT, script_pubkey),)
    spend = CTransaction(
        [CTxIn(COutPoint(b"\x22" * 32, 0), CScript(), 0xFFFFFFFE)],
        [],
    )
    return leaf_script, control, script_pubkey, spend, spent_outputs


def test_invalid_taproot_internal_key_is_a_validation_error() -> None:
    script = CScript([OP_1], name="valid-leaf")
    leaf_script, control, script_pubkey, spend, spent_outputs = (
        _taproot_scriptpath_spend(script)
    )
    invalid_control = control[:1] + b"\xff" * 32 + control[33:]

    with pytest.raises(ValidationError):
        VerifyScript(
            CScript(),
            script_pubkey,
            spend,
            0,
            flags=TAPROOT_FLAGS,
            amount=AMOUNT,
            witness=CScriptWitness([leaf_script, invalid_control]),
            spent_outputs=spent_outputs,
        )


def test_truncated_tapscript_prescan_is_a_validation_error() -> None:
    script = CScript(b"\x4c", name="truncated-pushdata1")
    leaf_script, control, script_pubkey, spend, spent_outputs = (
        _taproot_scriptpath_spend(script)
    )

    with pytest.raises(ValidationError):
        VerifyScript(
            CScript(),
            script_pubkey,
            spend,
            0,
            flags=TAPROOT_FLAGS,
            amount=AMOUNT,
            witness=CScriptWitness([leaf_script, control]),
            spent_outputs=spent_outputs,
        )
