# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import hashlib
import json
import unittest

from typing import Any, List, Mapping, Sequence, Tuple

from bitcointx.core import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    CTxWitness,
    ValidationError,
)
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OP_0,
    OP_1,
    OP_DROP,
    OP_DUP,
    OP_VERIFY,
    TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    VerifyScript,
    VerifyScriptWithTrace,
)
from bitcointx.wallet import CCoinKey, P2TRCoinAddress


TAPROOT_FLAGS = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
}
SEGWIT_FLAGS = {SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS}


def _dummy_transaction() -> CTransaction:
    return CTransaction(
        [CTxIn(COutPoint(b'\x01' * 32, 0))],
        [CTxOut(0, CScript([OP_1]))],
    )


def _make_tapscript_spend(
    script: CScript,
) -> Tuple[CScript, CScriptWitness, CTransaction]:
    key = CCoinKey.from_secret_bytes(b'\x21' * 32)
    tree = TaprootScriptTree([script], internal_pubkey=key.xonly_pub)
    leaf_name = script.name
    assert leaf_name is not None
    script_and_control = tree.get_script_with_control_block(leaf_name)
    assert script_and_control is not None
    committed_script, control = script_and_control
    script_pubkey = P2TRCoinAddress.from_script_tree(tree).to_scriptPubKey()
    witness = CScriptWitness([committed_script, control])

    value = 100_000
    credit = CTransaction(
        [CTxIn(COutPoint(), CScript([OP_0, OP_0]))],
        [CTxOut(value, script_pubkey)],
    )
    spend = CTransaction(
        [CTxIn(COutPoint(credit.GetTxid(), 0))],
        [CTxOut(value, CScript([OP_1]))],
        witness=CTxWitness([CTxInWitness(witness)]),
    )
    return script_pubkey, witness, spend


def _make_p2wsh_true_spend(
) -> Tuple[CScript, CScriptWitness, CTransaction]:
    witness_script = CScript([OP_1])
    program = hashlib.sha256(witness_script).digest()
    return (
        CScript([OP_0, program]),
        CScriptWitness([bytes(witness_script)]),
        _dummy_transaction(),
    )


class TestScriptEvaluationTraceLimits(unittest.TestCase):

    @staticmethod
    def _truncation_steps(
        steps: Sequence[Mapping[str, Any]],
    ) -> List[Mapping[str, Any]]:
        return [
            step for step in steps
            if step.get('step') == 'trace_truncated'
        ]

    def assert_single_terminal_marker(
        self, steps: Sequence[Mapping[str, Any]], *,
        phase: str, cap_text: str
    ) -> None:
        markers = self._truncation_steps(steps)
        self.assertEqual(len(markers), 1)
        marker = markers[0]
        self.assertIs(marker, steps[-1])
        self.assertEqual(
            list(marker),
            [
                'pc', 'kind', 'opcode_name', 'step', 'phase',
                'stack_before', 'stack_after', 'error',
            ],
        )
        self.assertEqual(
            {key: value for key, value in marker.items() if key != 'error'},
            {
                'pc': -1,
                'kind': 'validator',
                'opcode_name': 'trace_truncated',
                'step': 'trace_truncated',
                'phase': phase,
                'stack_before': [],
                'stack_after': [],
            },
        )
        self.assertIn(cap_text, marker['error'])
        self.assertIn('step', marker['error'])

    def test_default_step_cap_truncates_valid_large_tapscript(self) -> None:
        pair_count = 10_001
        script = CScript(
            bytes([int(OP_1)])
            + bytes([int(OP_DUP), int(OP_DROP)]) * pair_count,
            name='default_trace_cap',
        )
        script_pubkey, witness, spend = _make_tapscript_spend(script)

        VerifyScript(
            CScript(), script_pubkey, spend, 0,
            flags=TAPROOT_FLAGS, witness=witness,
        )
        ok, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, spend, 0,
            flags=TAPROOT_FLAGS, witness=witness,
        )

        self.assertTrue(ok)
        self.assertIsNone(error)
        self.assertLessEqual(len(steps), 20_001)
        self.assert_single_terminal_marker(
            steps,
            phase='witnessScript',
            cap_text='max_trace_steps=20000',
        )

    def test_explicit_byte_cap_keeps_verdict_and_one_marker(self) -> None:
        transaction = _dummy_transaction()

        ok, steps, error = VerifyScriptWithTrace(
            CScript(), CScript([OP_1]), transaction, 0,
            flags=set(), max_trace_steps=None, max_trace_bytes=1,
        )

        self.assertTrue(ok)
        self.assertIsNone(error)
        self.assertEqual(len(steps), 1)
        self.assert_single_terminal_marker(
            steps,
            phase='scriptPubKey',
            cap_text='max_trace_bytes=1',
        )

    def test_none_caps_are_unlimited_past_default_step_limit(self) -> None:
        pair_count = 10_001
        script = CScript(
            bytes([int(OP_1)])
            + bytes([int(OP_DUP), int(OP_DROP)]) * pair_count,
            name='unlimited_trace',
        )
        script_pubkey, witness, spend = _make_tapscript_spend(script)

        ok, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, spend, 0,
            flags=TAPROOT_FLAGS, witness=witness,
            max_trace_steps=None, max_trace_bytes=None,
        )

        self.assertTrue(ok)
        self.assertIsNone(error)
        self.assertEqual(len(steps), 2 * pair_count + 6)
        self.assertEqual(self._truncation_steps(steps), [])

    def test_witness_bookkeeping_truncation_uses_scriptpubkey_phase(
        self,
    ) -> None:
        script_pubkey, witness, transaction = _make_p2wsh_true_spend()

        ok, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction, 0,
            flags=SEGWIT_FLAGS, witness=witness,
            max_trace_steps=2, max_trace_bytes=None,
        )

        self.assertTrue(ok)
        self.assertIsNone(error)
        self.assertEqual(len(steps), 3)
        self.assert_single_terminal_marker(
            steps,
            phase='scriptPubKey',
            cap_text='max_trace_steps=2',
        )
        self.assertNotEqual(steps[-1]['phase'], 'witness')

    def test_verification_continues_to_failure_after_truncation(self) -> None:
        transaction = _dummy_transaction()
        failing_script = CScript([
            OP_1, OP_DUP, OP_DROP, OP_0, OP_VERIFY,
        ])

        with self.assertRaises(ValidationError):
            VerifyScript(
                CScript(), failing_script, transaction, 0, flags=set()
            )

        ok, steps, error = VerifyScriptWithTrace(
            CScript(), failing_script, transaction, 0,
            flags=set(), max_trace_steps=2, max_trace_bytes=None,
        )

        self.assertFalse(ok)
        self.assertIn('OP_VERIFY failed', error or '')
        self.assertEqual(len(steps), 3)
        self.assert_single_terminal_marker(
            steps,
            phase='scriptPubKey',
            cap_text='max_trace_steps=2',
        )

    def test_small_trace_preserves_serialized_payload(self) -> None:
        script_pubkey, witness, transaction = _make_p2wsh_true_spend()

        default_result = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction, 0,
            flags=SEGWIT_FLAGS, witness=witness,
        )
        unlimited_result = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction, 0,
            flags=SEGWIT_FLAGS, witness=witness,
            max_trace_steps=None, max_trace_bytes=None,
        )

        expected = (
            '[{"pc":0,"opcode":0,"opcode_name":"OP_0",'
            '"stack_before":[],"stack_after":[""],'
            '"phase":"scriptPubKey"},'
            '{"pc":1,"opcode":32,"opcode_name":"unknown opcode",'
            '"stack_before":[""],"stack_after":["",'
            '"4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3'
            '3260"],"phase":"scriptPubKey"},'
            '{"pc":-1,"opcode_name":"witness_program_match",'
            '"kind":"validator","step":"witness_program_match",'
            '"phase":"witness","witness_version":0,"program_hex":'
            '"4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3'
            '3260","p2sh_wrapped":false,"stack_before":[],'
            '"stack_after":[]},'
            '{"pc":-1,"opcode_name":"witness item 1/1",'
            '"kind":"validator","step":"witness_load",'
            '"phase":"witness","witness_index":0,"witness_total":1,'
            '"stack_before":[],"stack_after":["51"]},'
            '{"pc":-1,"opcode_name":"witness_script_check",'
            '"kind":"validator","step":"witness_script_check",'
            '"phase":"witness","script_hex":"51","sha256_hex":'
            '"4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3'
            '3260","program_hex":'
            '"4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3'
            '3260","stack_before":["51"],"stack_after":[]},'
            '{"pc":0,"opcode":81,"opcode_name":"OP_1",'
            '"stack_before":[],"stack_after":["01"],'
            '"phase":"witnessScript"}]'
        )
        for name, (ok, steps, error) in (
            ('default', default_result),
            ('unlimited', unlimited_result),
        ):
            with self.subTest(name=name):
                self.assertTrue(ok)
                self.assertIsNone(error)
                serialized = json.dumps(
                    steps, ensure_ascii=False, separators=(',', ':')
                )
                self.assertEqual(serialized, expected)


if __name__ == '__main__':
    unittest.main()
