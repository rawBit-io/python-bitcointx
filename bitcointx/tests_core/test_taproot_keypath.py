import hashlib
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import pytest

from bitcointx.core import (
    CMutableTransaction,
    COutPoint,
    CTxIn,
    CTxOut,
    ValidationError,
    x,
)
from bitcointx.core.key import tap_tweak_pubkey
from bitcointx.wallet import CCoinKey
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OP_1,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_Type,
    SignatureHashSchnorr,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    VerifyScript,
    VerifyScriptError,
)
from bitcointx.core.serialize import BytesSerializer


FLAGS = {SCRIPT_VERIFY_WITNESS, SCRIPT_VERIFY_TAPROOT, SCRIPT_VERIFY_P2SH}

SK1 = CCoinKey.from_secret_bytes(
    x("0000000000000000000000000000000000000000000000000000000000000001")
)
SK2 = CCoinKey.from_secret_bytes(
    x("0000000000000000000000000000000000000000000000000000000000000002")
)


@dataclass
class TaprootSpend:
    key: CCoinKey
    hashtype: Optional[SIGHASH_Type] = None
    annex: Optional[bytes] = None
    amount: int = 50_000


def _p2tr_scriptpubkey(key: CCoinKey) -> CScript:
    tweaked = tap_tweak_pubkey(key.xonly_pub)[0]
    return CScript([OP_1, tweaked])


def _annex_hash(annex: Optional[bytes]) -> Optional[bytes]:
    if annex is None:
        return None
    return hashlib.sha256(BytesSerializer.serialize(annex)).digest()


def _build_tx(
    spends: Sequence[TaprootSpend],
    outputs: Sequence[Tuple[int, CScript]],
) -> Tuple[CMutableTransaction, List[CTxOut], List[CScript]]:
    tx = CMutableTransaction()
    tx.vin = [
        CTxIn(COutPoint(b"\x00" * 32, idx), CScript(), 0xFFFFFFFD)
        for idx, _ in enumerate(spends)
    ]
    tx.vout = [CTxOut(val, spk) for val, spk in outputs]

    script_pubkeys: List[CScript] = []
    spent_outputs: List[CTxOut] = []
    for spend in spends:
        spk = _p2tr_scriptpubkey(spend.key)
        script_pubkeys.append(spk)
        spent_outputs.append(CTxOut(spend.amount, spk))

    return tx, spent_outputs, script_pubkeys


def _sign_input(
    tx: CMutableTransaction,
    in_idx: int,
    spend: TaprootSpend,
    spent_outputs: Sequence[CTxOut],
) -> bytes:
    sh = SignatureHashSchnorr(
        tx,
        in_idx,
        spent_outputs,
        hashtype=spend.hashtype,
        annex_hash=_annex_hash(spend.annex),
    )
    sig = spend.key.sign_schnorr_tweaked(sh)
    return sig if spend.hashtype is None else sig + bytes([spend.hashtype])


def _verify_input(
    tx: CMutableTransaction,
    in_idx: int,
    script_pubkey: CScript,
    witness: CScriptWitness,
    spent_outputs: Sequence[CTxOut],
) -> None:
    VerifyScript(
        CScript(),  # empty scriptSig
        script_pubkey,
        tx,
        in_idx,
        flags=FLAGS,
        amount=spent_outputs[in_idx].nValue,
        witness=witness,
        spent_outputs=spent_outputs,
    )


def test_hashtype_default_and_all() -> None:
    outputs = [(1_000, CScript([OP_1]))]
    spends = [TaprootSpend(SK1)]
    tx, spent_outputs, spks = _build_tx(spends, outputs)

    sig_default = _sign_input(tx, 0, spends[0], spent_outputs)
    _verify_input(tx, 0, spks[0], CScriptWitness([sig_default]), spent_outputs)

    spends_all = [TaprootSpend(SK1, SIGHASH_Type(SIGHASH_ALL))]
    tx2, spent_outputs2, spks2 = _build_tx(spends_all, outputs)
    sig_all = _sign_input(tx2, 0, spends_all[0], spent_outputs2)
    _verify_input(tx2, 0, spks2[0], CScriptWitness([sig_all]), spent_outputs2)

    # DEFAULT sig mis-tagged as ALL should fail
    with pytest.raises(VerifyScriptError):
        _verify_input(tx, 0, spks[0], CScriptWitness([sig_default + b"\x01"]), spent_outputs)
    # ALL sig used as DEFAULT should fail
    with pytest.raises(VerifyScriptError):
        _verify_input(tx2, 0, spks2[0], CScriptWitness([sig_all[:64]]), spent_outputs2)


@pytest.mark.parametrize(
    "hashtype",
    [
        SIGHASH_Type(SIGHASH_NONE),
        SIGHASH_Type(SIGHASH_SINGLE),
        SIGHASH_Type(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
        SIGHASH_Type(SIGHASH_NONE | SIGHASH_ANYONECANPAY),
        SIGHASH_Type(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
    ],
)
def test_hashtype_variants(hashtype: SIGHASH_Type) -> None:
    outputs = [(2_000, CScript([OP_1])), (3_000, CScript([OP_1]))]
    spends = [TaprootSpend(SK1, hashtype)]
    tx, spent_outputs, spks = _build_tx(spends, outputs)
    sig = _sign_input(tx, 0, spends[0], spent_outputs)
    _verify_input(tx, 0, spks[0], CScriptWitness([sig]), spent_outputs)


@pytest.mark.parametrize("bad_ht", [0x04, 0x11, 0x80, 0xFF])
def test_invalid_hashtype_byte(bad_ht: int) -> None:
    outputs = [(2_000, CScript([OP_1]))]
    spends = [TaprootSpend(SK1)]
    tx, spent_outputs, spks = _build_tx(spends, outputs)
    sig = _sign_input(tx, 0, spends[0], spent_outputs)
    bad_sig = sig + bytes([bad_ht])
    with pytest.raises(VerifyScriptError):
        _verify_input(tx, 0, spks[0], CScriptWitness([bad_sig]), spent_outputs)


@pytest.mark.parametrize("siglen", [63, 66, 0])
def test_invalid_signature_lengths(siglen: int) -> None:
    outputs = [(1_000, CScript([OP_1]))]
    spends = [TaprootSpend(SK1)]
    tx, spent_outputs, spks = _build_tx(spends, outputs)
    bad_sig = b"\x01" * siglen
    with pytest.raises(VerifyScriptError):
        _verify_input(tx, 0, spks[0], CScriptWitness([bad_sig]), spent_outputs)


def test_sighash_single_without_output_fails() -> None:
    outputs: List[Tuple[int, CScript]] = []
    spends = [TaprootSpend(SK1, SIGHASH_Type(SIGHASH_SINGLE))]
    tx, spent_outputs, _ = _build_tx(spends, outputs)
    with pytest.raises((ValueError, IndexError)):
        _sign_input(tx, 0, spends[0], spent_outputs)


def test_annex_handling() -> None:
    outputs = [(1_000, CScript([OP_1]))]
    annex = b"\x50\xAA"
    spends = [TaprootSpend(SK1, None, annex)]
    tx, spent_outputs, spks = _build_tx(spends, outputs)
    sig = _sign_input(tx, 0, spends[0], spent_outputs)
    _verify_input(tx, 0, spks[0], CScriptWitness([sig, annex]), spent_outputs)

    # Signature without annex but annex present in witness -> digest mismatch
    sig_no_annex = _sign_input(tx, 0, TaprootSpend(SK1), spent_outputs)
    with pytest.raises(VerifyScriptError):
        _verify_input(tx, 0, spks[0], CScriptWitness([sig_no_annex, annex]), spent_outputs)

    # Signature with annex but annex omitted in witness -> digest mismatch
    with pytest.raises(VerifyScriptError):
        _verify_input(tx, 0, spks[0], CScriptWitness([sig]), spent_outputs)

    # Single-element starting with 0x50 is not treated as annex, just a bad sig
    with pytest.raises(VerifyScriptError):
        _verify_input(tx, 0, spks[0], CScriptWitness([b"\x50"]), spent_outputs)

    # Annex of length 1 (just 0x50) is valid
    annex_short = b"\x50"
    spends_short = [TaprootSpend(SK1, None, annex_short)]
    tx2, spent_outputs2, spks2 = _build_tx(spends_short, outputs)
    sig2 = _sign_input(tx2, 0, spends_short[0], spent_outputs2)
    _verify_input(tx2, 0, spks2[0], CScriptWitness([sig2, annex_short]), spent_outputs2)


def test_multi_input_independent_hashtypes() -> None:
    outputs = [(5_000, CScript([OP_1]))]
    spends = [
        TaprootSpend(SK1, None),
        TaprootSpend(SK2, SIGHASH_Type(SIGHASH_ALL | SIGHASH_ANYONECANPAY)),
    ]
    tx, spent_outputs, spks = _build_tx(spends, outputs)

    sig0 = _sign_input(tx, 0, spends[0], spent_outputs)
    sig1 = _sign_input(tx, 1, spends[1], spent_outputs)

    _verify_input(tx, 0, spks[0], CScriptWitness([sig0]), spent_outputs)
    _verify_input(tx, 1, spks[1], CScriptWitness([sig1]), spent_outputs)
