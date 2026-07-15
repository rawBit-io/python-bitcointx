# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import hashlib
import unittest

from typing import List, Tuple

from bitcointx.core import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    CTxWitness,
    ValidationError,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OPCODE_NAMES,
    OP_0,
    OP_1,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_DROP,
    OP_EQUAL,
    OP_NOP1,
    OP_NOP2,
    OP_NOP3,
    OP_NOP4,
    OP_NOP5,
    OP_NOP6,
    OP_NOP7,
    OP_NOP8,
    OP_NOP9,
    OP_NOP10,
    OP_NOT,
    OP_RESERVED,
    TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_STRICTENC,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    VerifyScript,
    VerifyScriptWithTrace,
)
from bitcointx.wallet import CCoinKey, P2TRCoinAddress


TAPROOT_FLAGS = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
}


def _make_spend(
    script_pubkey: CScript,
    *,
    script_sig: CScript = CScript(),
    witness: CScriptWitness = CScriptWitness(),
    n_version: int = 2,
    n_lock_time: int = 0,
    n_sequence: int = 0,
) -> Tuple[CTransaction, CTransaction]:
    value = 100_000
    credit = CTransaction(
        [CTxIn(COutPoint(), CScript([OP_0, OP_0]))],
        [CTxOut(value, script_pubkey)],
    )
    spend = CTransaction(
        [
            CTxIn(
                COutPoint(credit.GetTxid(), 0),
                script_sig,
                nSequence=n_sequence,
            )
        ],
        [CTxOut(value, CScript([OP_1]))],
        nVersion=n_version,
        nLockTime=n_lock_time,
        witness=CTxWitness([CTxInWitness(witness)]),
    )
    return credit, spend


def _make_tapscript_spend(
    script: CScript,
    leaf_name: str,
    stack: List[bytes],
) -> Tuple[CScript, CScriptWitness, CTransaction, CTransaction]:
    key = CCoinKey.from_secret_bytes(b"\x11" * 32)
    tree = TaprootScriptTree([script], internal_pubkey=key.xonly_pub)
    script_and_control = tree.get_script_with_control_block(leaf_name)
    assert script_and_control is not None
    committed_script, control = script_and_control
    script_pubkey = P2TRCoinAddress.from_script_tree(tree).to_scriptPubKey()
    witness = CScriptWitness(stack + [committed_script, control])
    credit, spend = _make_spend(script_pubkey, witness=witness)
    return script_pubkey, witness, credit, spend


def _verify_witness_program(
    witness_program: CScript,
    *,
    wrapped: bool,
    flags: set,
) -> None:
    witness = CScriptWitness()
    if wrapped:
        script_sig = CScript([bytes(witness_program)])
        script_pubkey = witness_program.to_p2sh_scriptPubKey()
    else:
        script_sig = CScript()
        script_pubkey = witness_program

    _, spend = _make_spend(
        script_pubkey, script_sig=script_sig, witness=witness
    )
    VerifyScript(
        script_sig,
        script_pubkey,
        spend,
        0,
        flags=flags,
        witness=witness,
    )


class TestScriptEvalPolicyFixes(unittest.TestCase):

    def test_trace_rejects_witness_without_p2sh_as_false_tuple(self) -> None:
        script_pubkey = CScript([OP_1])
        _, spend = _make_spend(script_pubkey)

        with self.assertRaisesRegex(
            ValueError, "SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH"
        ):
            VerifyScript(
                CScript(),
                script_pubkey,
                spend,
                0,
                flags={SCRIPT_VERIFY_WITNESS},
            )

        ok, steps, error = VerifyScriptWithTrace(
            CScript(),
            script_pubkey,
            spend,
            0,
            flags={SCRIPT_VERIFY_WITNESS},
        )

        self.assertFalse(ok)
        self.assertIsInstance(steps, list)
        self.assertEqual(
            error, "SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH"
        )

    def test_cleanstack_without_witness_uses_each_entrypoint_convention(
        self,
    ) -> None:
        script_pubkey = CScript([OP_1])
        _, spend = _make_spend(script_pubkey)
        flags = {SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_CLEANSTACK}

        with self.assertRaisesRegex(
            ValueError,
            "SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS",
        ):
            VerifyScript(
                CScript(), script_pubkey, spend, 0, flags=flags
            )

        ok, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, spend, 0, flags=flags
        )
        self.assertFalse(ok)
        self.assertIsInstance(steps, list)
        self.assertEqual(
            error, "SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS"
        )

    def test_signatureless_tapscript_does_not_require_prevouts(self) -> None:
        scripts = (
            ("op_true", CScript([OP_1], name="op_true")),
            (
                "op_success",
                CScript(bytes([int(OP_RESERVED)]), name="op_success"),
            ),
        )

        for name, script in scripts:
            with self.subTest(name=name):
                script_pubkey, witness, _, spend = _make_tapscript_spend(
                    script, name, []
                )
                VerifyScript(
                    CScript(),
                    script_pubkey,
                    spend,
                    0,
                    flags=TAPROOT_FLAGS,
                    witness=witness,
                    spent_outputs=None,
                )

    def test_empty_tapscript_signatures_do_not_require_prevouts(self) -> None:
        pubkey = CCoinKey.from_secret_bytes(b"\x12" * 32).xonly_pub
        cases = (
            (
                "checksig",
                CScript(
                    [pubkey, OP_CHECKSIG, OP_NOT], name="empty_checksig"
                ),
                "empty_checksig",
                [b""],
            ),
            (
                "checksigadd",
                CScript(
                    [pubkey, OP_CHECKSIGADD, OP_0, OP_EQUAL],
                    name="empty_checksigadd",
                ),
                "empty_checksigadd",
                [b"", b""],
            ),
        )

        for case_name, script, leaf_name, stack in cases:
            with self.subTest(case=case_name):
                script_pubkey, witness, _, spend = _make_tapscript_spend(
                    script, leaf_name, stack
                )
                VerifyScript(
                    CScript(),
                    script_pubkey,
                    spend,
                    0,
                    flags=TAPROOT_FLAGS,
                    witness=witness,
                    spent_outputs=None,
                )

    def test_tapscript_requests_prevouts_only_at_a_real_sighash(self) -> None:
        pubkey = CCoinKey.from_secret_bytes(b"\x13" * 32).xonly_pub
        cases = (
            (
                "checksig",
                lambda sig: [sig],
                CScript([pubkey, OP_CHECKSIG], name="context_checksig"),
                "context_checksig",
            ),
            (
                "checksigadd",
                lambda sig: [sig, b""],
                CScript(
                    [pubkey, OP_CHECKSIGADD], name="context_checksigadd"
                ),
                "context_checksigadd",
            ),
        )

        for case_name, stack_for_sig, script, leaf_name in cases:
            with self.subTest(case=case_name, signature="malformed"):
                script_pubkey, witness, _, spend = _make_tapscript_spend(
                    script, leaf_name, stack_for_sig(b"\x01")
                )
                with self.assertRaisesRegex(
                    ValidationError, "invalid schnorr signature size"
                ):
                    VerifyScript(
                        CScript(),
                        script_pubkey,
                        spend,
                        0,
                        flags=TAPROOT_FLAGS,
                        witness=witness,
                        spent_outputs=None,
                    )

            with self.subTest(case=case_name, signature="well-formed"):
                script_pubkey, witness, _, spend = _make_tapscript_spend(
                    script, leaf_name, stack_for_sig(b"\x00" * 64)
                )
                with self.assertRaisesRegex(
                    ValidationError, "missing taproot context for sighash"
                ):
                    VerifyScript(
                        CScript(),
                        script_pubkey,
                        spend,
                        0,
                        flags=TAPROOT_FLAGS,
                        witness=witness,
                        spent_outputs=None,
                    )

    def test_taproot_keypath_distinguishes_none_from_empty_prevouts(self) -> None:
        key = CCoinKey.from_secret_bytes(b"\x14" * 32)
        script_pubkey = P2TRCoinAddress.from_xonly_pubkey(
            key.xonly_pub
        ).to_scriptPubKey()

        invalid_witness = CScriptWitness([b"\x01"])
        _, spend = _make_spend(script_pubkey, witness=invalid_witness)
        with self.assertRaisesRegex(
            ValidationError, "invalid schnorr signature size"
        ):
            VerifyScript(
                CScript(),
                script_pubkey,
                spend,
                0,
                flags=TAPROOT_FLAGS,
                witness=invalid_witness,
                spent_outputs=None,
            )

        shaped_witness = CScriptWitness([b"\x00" * 64])
        _, spend = _make_spend(script_pubkey, witness=shaped_witness)
        with self.assertRaisesRegex(
            ValidationError,
            "spent_outputs are required for taproot key path verification",
        ):
            VerifyScript(
                CScript(),
                script_pubkey,
                spend,
                0,
                flags=TAPROOT_FLAGS,
                witness=shaped_witness,
                spent_outputs=None,
            )

        with self.assertRaisesRegex(
            ValueError, "number of spent_outputs is not equal to number of inputs"
        ):
            VerifyScript(
                CScript(),
                script_pubkey,
                spend,
                0,
                flags=TAPROOT_FLAGS,
                witness=shaped_witness,
                spent_outputs=[],
            )

    def test_empty_signature_still_checks_strictenc_pubkeys(self) -> None:
        malformed_pubkey = b"\x02"
        cases = (
            (
                "checksig",
                CScript([b""]),
                CScript([malformed_pubkey, OP_CHECKSIG, OP_NOT]),
            ),
            (
                "checkmultisig",
                CScript([b"", b""]),
                CScript(
                    [1, malformed_pubkey, 1, OP_CHECKMULTISIG, OP_NOT]
                ),
            ),
        )

        for case_name, script_sig, script_pubkey in cases:
            with self.subTest(case=case_name):
                _, spend = _make_spend(
                    script_pubkey, script_sig=script_sig
                )
                with self.assertRaisesRegex(
                    ValidationError, "unknown pubkey type"
                ):
                    VerifyScript(
                        script_sig,
                        script_pubkey,
                        spend,
                        0,
                        flags={SCRIPT_VERIFY_STRICTENC},
                    )

    def test_empty_signature_with_valid_pubkey_remains_allowed(self) -> None:
        pubkey = bytes(CKey.from_secret_bytes(b"\x15" * 32).pub)
        cases = (
            (
                CScript([b""]),
                CScript([pubkey, OP_CHECKSIG, OP_NOT]),
            ),
            (
                CScript([b"", b""]),
                CScript([1, pubkey, 1, OP_CHECKMULTISIG, OP_NOT]),
            ),
        )

        for script_sig, script_pubkey in cases:
            with self.subTest(opcode=script_pubkey.hex()):
                _, spend = _make_spend(
                    script_pubkey, script_sig=script_sig
                )
                VerifyScript(
                    script_sig,
                    script_pubkey,
                    spend,
                    0,
                    flags={SCRIPT_VERIFY_STRICTENC},
                )

    def test_empty_signature_still_checks_witness_pubkey_type(self) -> None:
        compressed = bytes(CKey.from_secret_bytes(b"\x16" * 32).pub)
        uncompressed = bytes(
            CKey.from_secret_bytes(b"\x16" * 32, compressed=False).pub
        )
        flags = {
            SCRIPT_VERIFY_P2SH,
            SCRIPT_VERIFY_WITNESS,
            SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
        }

        for opcode_name, witness_script, witness_stack in (
            (
                "checksig",
                CScript([OP_CHECKSIG, OP_NOT]),
                lambda pubkey: [b"", pubkey],
            ),
            (
                "checkmultisig",
                CScript([1, uncompressed, 1, OP_CHECKMULTISIG, OP_NOT]),
                lambda pubkey: [b"", b""],
            ),
        ):
            if opcode_name == "checkmultisig":
                valid_script = CScript(
                    [1, compressed, 1, OP_CHECKMULTISIG, OP_NOT]
                )
            else:
                valid_script = witness_script

            with self.subTest(opcode=opcode_name, pubkey="uncompressed"):
                stack = witness_stack(uncompressed)
                witness = CScriptWitness(stack + [bytes(witness_script)])
                script_pubkey = CScript(
                    [OP_0, hashlib.sha256(witness_script).digest()]
                )
                _, spend = _make_spend(script_pubkey, witness=witness)
                with self.assertRaisesRegex(
                    ValidationError, "witness pubkey is not compressed"
                ):
                    VerifyScript(
                        CScript(),
                        script_pubkey,
                        spend,
                        0,
                        flags=flags,
                        witness=witness,
                    )

            with self.subTest(opcode=opcode_name, pubkey="compressed"):
                stack = witness_stack(compressed)
                witness = CScriptWitness(stack + [bytes(valid_script)])
                script_pubkey = CScript(
                    [OP_0, hashlib.sha256(valid_script).digest()]
                )
                _, spend = _make_spend(script_pubkey, witness=witness)
                VerifyScript(
                    CScript(),
                    script_pubkey,
                    spend,
                    0,
                    flags=flags,
                    witness=witness,
                )

    def test_pay_to_anchor_exemption_is_native_only(self) -> None:
        flags = {
            SCRIPT_VERIFY_P2SH,
            SCRIPT_VERIFY_WITNESS,
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        }
        pay_to_anchor = CScript([OP_1, b"\x4e\x73"])

        _verify_witness_program(
            pay_to_anchor, wrapped=False, flags=flags
        )
        with self.assertRaisesRegex(
            ValidationError, "upgradeable witness program is not accepted"
        ):
            _verify_witness_program(
                pay_to_anchor, wrapped=True, flags=flags
            )

        nearby_program = CScript([OP_1, b"\x4e\x74"])
        with self.assertRaisesRegex(
            ValidationError, "upgradeable witness program is not accepted"
        ):
            _verify_witness_program(
                nearby_program, wrapped=False, flags=flags
            )

    def test_taproot_off_native_v1_32_bypasses_discourage(self) -> None:
        flags = {
            SCRIPT_VERIFY_P2SH,
            SCRIPT_VERIFY_WITNESS,
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        }
        witness_program = CScript([OP_1, b"\x22" * 32])

        _verify_witness_program(
            witness_program, wrapped=False, flags=flags
        )
        with self.assertRaisesRegex(
            ValidationError, "upgradeable witness program is not accepted"
        ):
            _verify_witness_program(
                witness_program, wrapped=True, flags=flags
            )

    def test_nop1_through_nop10_discourage_matrix(self) -> None:
        nop_matrix = (
            ("NOP1", OP_NOP1, False),
            ("NOP2/CLTV", OP_NOP2, True),
            ("NOP3/CSV", OP_NOP3, True),
            ("NOP4", OP_NOP4, False),
            ("NOP5", OP_NOP5, False),
            ("NOP6", OP_NOP6, False),
            ("NOP7", OP_NOP7, False),
            ("NOP8", OP_NOP8, False),
            ("NOP9", OP_NOP9, False),
            ("NOP10", OP_NOP10, False),
        )

        for name, opcode, is_assigned in nop_matrix:
            script_pubkey = CScript([OP_1, opcode, OP_1])
            _, spend = _make_spend(script_pubkey)
            with self.subTest(opcode=name, discourage=False):
                VerifyScript(
                    CScript(), script_pubkey, spend, 0, flags=set()
                )

            with self.subTest(opcode=name, discourage=True):
                flags = {SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS}
                if is_assigned:
                    VerifyScript(
                        CScript(), script_pubkey, spend, 0, flags=flags
                    )
                else:
                    with self.assertRaises(ValidationError):
                        VerifyScript(
                            CScript(),
                            script_pubkey,
                            spend,
                            0,
                            flags=flags,
                        )

    def test_assigned_locktime_opcode_flag_matrix(self) -> None:
        cases = (
            (
                "CLTV",
                OP_CHECKLOCKTIMEVERIFY,
                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
            ),
            (
                "CSV",
                OP_CHECKSEQUENCEVERIFY,
                SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            ),
        )

        for name, opcode, enable_flag in cases:
            script_pubkey = CScript([OP_0, opcode, OP_DROP, OP_1])
            _, spend = _make_spend(
                script_pubkey,
                n_version=2,
                n_lock_time=0,
                n_sequence=0,
            )
            for enabled in (False, True):
                for discouraged in (False, True):
                    flags = set()
                    if enabled:
                        flags.add(enable_flag)
                    if discouraged:
                        flags.add(
                            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
                        )

                    with self.subTest(
                        opcode=name,
                        enabled=enabled,
                        discouraged=discouraged,
                    ):
                        VerifyScript(
                            CScript(),
                            script_pubkey,
                            spend,
                            0,
                            flags=flags,
                        )

    def test_checksigadd_has_a_canonical_opcode_name(self) -> None:
        self.assertEqual(OPCODE_NAMES[OP_CHECKSIGADD], "OP_CHECKSIGADD")
        self.assertEqual(str(OP_CHECKSIGADD), "OP_CHECKSIGADD")


if __name__ == "__main__":
    unittest.main()
