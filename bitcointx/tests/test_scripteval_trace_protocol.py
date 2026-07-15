# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import hashlib
import unittest

from typing import List, NamedTuple, Optional, Sequence, Set, Tuple

from bitcointx.core import (
    CoreCoinParams,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OP_0,
    OP_1,
    OP_CAT,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    OP_PUSHDATA1,
    OP_RESERVED,
    SIGVERSION_TAPROOT,
    SignatureHashSchnorr,
    TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    MAX_STACK_ITEMS,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    ScriptVerifyFlag_Type,
    TraceStep,
    VerifyScriptWithTrace,
)
from bitcointx.core.serialize import BytesSerializer
from bitcointx.wallet import CCoinKey, P2TRCoinAddress


TAPROOT_FLAGS = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
}
AMOUNT = 50_000


class ScriptPathCase(NamedTuple):
    script_pubkey: CScript
    script: CScript
    control: bytes
    witness: CScriptWitness
    transaction: CTransaction
    spent_outputs: Tuple[CTxOut, ...]
    internal_key: CCoinKey


class KeyPathTrace(NamedTuple):
    steps: List[TraceStep]
    program: bytes
    signature: bytes
    sighash: bytes
    annex: Optional[bytes]
    annex_hash: Optional[bytes]


def _spending_transaction(
    script_pubkey: CScript, seed: int,
) -> Tuple[CTransaction, Tuple[CTxOut, ...]]:
    spent_outputs = (CTxOut(AMOUNT, script_pubkey),)
    transaction = CTransaction(
        [
            CTxIn(
                COutPoint(bytes([seed]) * 32, 0),
                CScript(),
                0xFFFFFFFE,
            )
        ],
        [CTxOut(AMOUNT - 1_000, CScript([OP_1]))],
        nVersion=2,
    )
    return transaction, spent_outputs


def _script_path_case(
    script: CScript,
    *,
    leaf_version: Optional[int] = None,
    stack: Sequence[bytes] = (),
    output_script: Optional[CScript] = None,
) -> ScriptPathCase:
    internal_key = CCoinKey.from_secret_bytes(b'\x31' * 32)
    if leaf_version is None:
        tree = TaprootScriptTree(
            [script], internal_pubkey=internal_key.xonly_pub
        )
    else:
        tree = TaprootScriptTree(
            [script],
            internal_pubkey=internal_key.xonly_pub,
            leaf_version=leaf_version,
        )
    script_and_control = tree.get_script_with_control_block(script.name or '')
    assert script_and_control is not None
    committed_script, control = script_and_control
    if output_script is None:
        script_pubkey = P2TRCoinAddress.from_script_tree(
            tree
        ).to_scriptPubKey()
    else:
        script_pubkey = output_script
    transaction, spent_outputs = _spending_transaction(script_pubkey, 0x41)
    witness = CScriptWitness(list(stack) + [committed_script, control])
    return ScriptPathCase(
        script_pubkey=script_pubkey,
        script=committed_script,
        control=control,
        witness=witness,
        transaction=transaction,
        spent_outputs=spent_outputs,
        internal_key=internal_key,
    )


def _trace_script_path(
    case: ScriptPathCase,
    *,
    flags: Set[ScriptVerifyFlag_Type] = TAPROOT_FLAGS,
) -> Tuple[bool, List[TraceStep], Optional[str]]:
    return VerifyScriptWithTrace(
        CScript(),
        case.script_pubkey,
        case.transaction,
        0,
        flags=flags,
        amount=AMOUNT,
        witness=case.witness,
        spent_outputs=case.spent_outputs,
    )


def _key_path_trace(annex: Optional[bytes] = None) -> KeyPathTrace:
    key = CCoinKey.from_secret_bytes(b'\x21' * 32)
    script_pubkey = P2TRCoinAddress.from_xonly_pubkey(
        key.xonly_pub
    ).to_scriptPubKey()
    transaction, spent_outputs = _spending_transaction(script_pubkey, 0x42)
    annex_hash = None
    if annex is not None:
        annex_hash = hashlib.sha256(
            BytesSerializer.serialize(annex)
        ).digest()
    sighash = SignatureHashSchnorr(
        transaction,
        0,
        spent_outputs,
        sigversion=SIGVERSION_TAPROOT,
        annex_hash=annex_hash,
    )
    signature = key.sign_schnorr_tweaked(sighash, aux=b'\x00' * 32)
    witness_items = [signature]
    if annex is not None:
        witness_items.append(annex)
    valid, steps, error = VerifyScriptWithTrace(
        CScript(),
        script_pubkey,
        transaction,
        0,
        flags=TAPROOT_FLAGS,
        amount=AMOUNT,
        witness=CScriptWitness(witness_items),
        spent_outputs=spent_outputs,
    )
    assert valid
    assert error is None
    return KeyPathTrace(
        steps=steps,
        program=script_pubkey.witness_program(),
        signature=signature,
        sighash=sighash,
        annex=annex,
        annex_hash=annex_hash,
    )


class TestTraceProtocol(unittest.TestCase):

    @staticmethod
    def _dummy_transaction() -> CTransaction:
        return CTransaction(
            [CTxIn(COutPoint(b'\x01' * 32, 0))],
            [CTxOut(0, CScript([OP_1]))],
        )

    def test_every_opcode_step_pins_branch_active_on_entry(self) -> None:
        script_pubkey = CScript([
            OP_0,
            OP_IF,
            b'\xaa',
            OP_DROP,
            OP_ELSE,
            b'\xbb',
            OP_DROP,
            OP_ENDIF,
            OP_1,
        ])

        valid, typed_steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, self._dummy_transaction(), 0
        )

        self.assertTrue(valid)
        self.assertIsNone(error)
        steps = [dict(step) for step in typed_steps]
        self.assertEqual(
            [
                (step['opcode_name'], step['branch_active'])
                for step in steps
            ],
            [
                ('OP_0', True),
                ('OP_IF', True),
                ('unknown opcode', False),
                ('OP_DROP', False),
                ('OP_ELSE', False),
                ('unknown opcode', True),
                ('OP_DROP', True),
                ('OP_ENDIF', True),
                ('OP_1', True),
            ],
        )
        self.assertTrue(all(
            set(step) == {
                'pc',
                'opcode',
                'opcode_name',
                'stack_before',
                'stack_after',
                'phase',
                'branch_active',
            }
            for step in steps
        ))

    def test_failed_opcode_records_inactive_branch_state(self) -> None:
        script_pubkey = CScript([
            OP_0,
            OP_IF,
            OP_CAT,
            OP_ENDIF,
            OP_1,
        ])

        valid, typed_steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, self._dummy_transaction(), 0
        )
        failures = [
            dict(step) for step in typed_steps
            if step.get('failed') is True
        ]

        self.assertFalse(valid)
        self.assertIn('OP_CAT is disabled', error or '')
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]['opcode_name'], 'OP_CAT')
        self.assertEqual(failures[0]['phase'], 'scriptPubKey')
        self.assertIs(failures[0]['branch_active'], False)
        self.assertNotIn('error_code', failures[0])

    def test_key_path_full_event_sequence_is_frozen(self) -> None:
        trace = _key_path_trace()
        sig_hex = trace.signature.hex()
        program_hex = trace.program.hex()

        self.assertEqual(
            [dict(step) for step in trace.steps],
            [
                {
                    'pc': 0,
                    'opcode': int(OP_1),
                    'opcode_name': 'OP_1',
                    'stack_before': [],
                    'stack_after': ['01'],
                    'phase': 'scriptPubKey',
                    'branch_active': True,
                },
                {
                    'pc': 1,
                    'opcode': 32,
                    'opcode_name': 'unknown opcode',
                    'stack_before': ['01'],
                    'stack_after': ['01', program_hex],
                    'phase': 'scriptPubKey',
                    'branch_active': True,
                },
                {
                    'pc': -1,
                    'opcode_name': 'taproot_witness',
                    'phase': 'taproot',
                    'step': 'witness_stack',
                    'stack_before': [sig_hex],
                    'stack_after': [sig_hex],
                },
                {
                    'pc': -1,
                    'opcode_name': 'taproot_sighash',
                    'phase': 'taproot',
                    'step': 'sighash',
                    'sigversion': 'tapsighash',
                    'hashtype': 0,
                    'hashtype_name': 'DEFAULT',
                    'sighash': trace.sighash.hex(),
                    'stack_before': [sig_hex],
                    'stack_after': [sig_hex],
                },
                {
                    'pc': -1,
                    'opcode_name': 'taproot_schnorr_verify',
                    'phase': 'taproot',
                    'step': 'schnorr_verify',
                    'pubkey': program_hex,
                    'signature': sig_hex,
                    'hashtype': 0,
                    'hashtype_name': 'DEFAULT',
                    'result': True,
                    'stack_before': [sig_hex],
                    'stack_after': ['01'],
                },
            ],
        )

    def test_script_path_full_event_sequence_is_frozen(self) -> None:
        case = _script_path_case(CScript([OP_1], name='committed'))
        valid, typed_steps, error = _trace_script_path(case)
        program_hex = case.script_pubkey.witness_program().hex()
        script_hex = case.script.hex()
        control_hex = case.control.hex()
        tapleaf_hash = CoreCoinParams.tapleaf_hasher(
            bytes([0xc0]) + BytesSerializer.serialize(bytes(case.script))
        )

        self.assertTrue(valid)
        self.assertIsNone(error)
        self.assertEqual(
            [dict(step) for step in typed_steps],
            [
                {
                    'pc': 0,
                    'opcode': int(OP_1),
                    'opcode_name': 'OP_1',
                    'stack_before': [],
                    'stack_after': ['01'],
                    'phase': 'scriptPubKey',
                    'branch_active': True,
                },
                {
                    'pc': 1,
                    'opcode': 32,
                    'opcode_name': 'unknown opcode',
                    'stack_before': ['01'],
                    'stack_after': ['01', program_hex],
                    'phase': 'scriptPubKey',
                    'branch_active': True,
                },
                {
                    'pc': -1,
                    'opcode_name': 'taproot_witness',
                    'phase': 'taproot',
                    'step': 'witness_stack',
                    'stack_before': [script_hex, control_hex],
                    'stack_after': [script_hex, control_hex],
                },
                {
                    'pc': -1,
                    'opcode_name': 'witness_script',
                    'phase': 'witnessScript',
                    'step': 'witness_script',
                    'script_hex': script_hex,
                    'stack_before': [],
                    'stack_after': [],
                    'committed': True,
                    'executed': True,
                },
                {
                    'pc': -1,
                    'opcode_name': 'taproot_control_block',
                    'phase': 'taproot',
                    'step': 'control_block',
                    'leaf_version': 0xc0,
                    'tapleaf_hash': tapleaf_hash.hex(),
                    'merkle_root': tapleaf_hash.hex(),
                    'internal_pubkey': case.internal_key.xonly_pub.hex(),
                    'tweaked_pubkey': program_hex,
                    'parity': bool(case.control[0] & 1),
                    'result': True,
                },
                {
                    'pc': 0,
                    'opcode': int(OP_1),
                    'opcode_name': 'OP_1',
                    'stack_before': [],
                    'stack_after': ['01'],
                    'phase': 'witnessScript',
                    'branch_active': True,
                },
            ],
        )

    def test_annex_follows_original_witness_with_exact_shape(self) -> None:
        trace = _key_path_trace(b'\x50\xaa')
        assert trace.annex is not None
        assert trace.annex_hash is not None
        sig_hex = trace.signature.hex()
        original_stack = [sig_hex, trace.annex.hex()]
        events = [dict(step) for step in trace.steps]
        witness_index = next(
            index for index, event in enumerate(events)
            if event.get('step') == 'witness_stack'
        )

        self.assertEqual(
            events[witness_index],
            {
                'pc': -1,
                'opcode_name': 'taproot_witness',
                'phase': 'taproot',
                'step': 'witness_stack',
                'stack_before': original_stack,
                'stack_after': original_stack,
            },
        )
        self.assertEqual(
            events[witness_index + 1],
            {
                'pc': -1,
                'kind': 'validator',
                'opcode_name': 'taproot_annex',
                'step': 'taproot_annex',
                'phase': 'taproot',
                'annex_hex': trace.annex.hex(),
                'annex_hash': trace.annex_hash.hex(),
                'stack_before': original_stack,
                'stack_after': [sig_hex],
            },
        )

    def test_op_success_event_exact_shape_for_both_policies(self) -> None:
        for discouraged in (False, True):
            with self.subTest(discouraged=discouraged):
                case = _script_path_case(
                    CScript(
                        bytes([int(OP_RESERVED)]), name='op_success'
                    ),
                    stack=[b'\xaa'],
                )
                flags = set(TAPROOT_FLAGS)
                if discouraged:
                    flags.add(SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)

                _, typed_steps, _ = _trace_script_path(case, flags=flags)
                op_success_events = [
                    dict(step) for step in typed_steps
                    if step.get('step') == 'op_success'
                ]
                witness_script_event = next(
                    dict(step) for step in typed_steps
                    if step.get('step') == 'witness_script'
                )

                self.assertTrue(witness_script_event['committed'])
                self.assertFalse(witness_script_event['executed'])
                self.assertEqual(
                    op_success_events,
                    [{
                        'pc': 0,
                        'kind': 'validator',
                        'opcode_name': 'op_success',
                        'step': 'op_success',
                        'phase': 'taproot',
                        'stack_before': ['aa'],
                        'stack_after': ['aa'],
                        'policy': (
                            'discouraged' if discouraged else 'ok'
                        ),
                    }],
                )

    def test_witness_script_marks_failed_commitment_unexecuted(self) -> None:
        other_key = CCoinKey.from_secret_bytes(b'\x32' * 32)
        mismatched_output = P2TRCoinAddress.from_xonly_pubkey(
            other_key.xonly_pub
        ).to_scriptPubKey()
        case = _script_path_case(
            CScript([OP_1], name='mismatched'),
            output_script=mismatched_output,
        )

        valid, typed_steps, _ = _trace_script_path(case)

        self.assertFalse(valid)
        self.assertEqual(typed_steps[-1].get('error_code'),
                         'TWEAK_MISMATCH')
        self.assertEqual(
            [
                dict(step) for step in typed_steps
                if step.get('step') == 'witness_script'
            ],
            [{
                'pc': -1,
                'opcode_name': 'witness_script',
                'phase': 'witnessScript',
                'step': 'witness_script',
                'script_hex': case.script.hex(),
                'stack_before': [],
                'stack_after': [],
                'committed': False,
                'executed': False,
            }],
        )

    def test_witness_script_marks_pre_execution_rejections_unexecuted(
        self,
    ) -> None:
        cases = (
            (
                'parse',
                _script_path_case(
                    CScript(
                        bytes([int(OP_PUSHDATA1)]), name='malformed'
                    )
                ),
            ),
            (
                'element-size',
                _script_path_case(
                    CScript([OP_1], name='large_element'),
                    stack=[b'\x01' * 521],
                ),
            ),
            (
                'stack-size',
                _script_path_case(
                    CScript([OP_1], name='large_stack'),
                    stack=[b''] * (MAX_STACK_ITEMS + 1),
                ),
            ),
        )

        for name, case in cases:
            with self.subTest(name=name):
                valid, typed_steps, _ = _trace_script_path(case)
                witness_script_event = next(
                    dict(step) for step in typed_steps
                    if step.get('step') == 'witness_script'
                )

                self.assertFalse(valid)
                self.assertTrue(witness_script_event['committed'])
                self.assertFalse(witness_script_event['executed'])

    def test_witness_script_marks_unknown_leaf_committed_unexecuted(
        self,
    ) -> None:
        case = _script_path_case(
            CScript([OP_1], name='future'), leaf_version=0xc2
        )

        valid, typed_steps, error = _trace_script_path(case)
        events = [dict(step) for step in typed_steps]

        self.assertTrue(valid)
        self.assertIsNone(error)
        self.assertEqual(
            [event.get('step') for event in events],
            [
                None,
                None,
                'witness_stack',
                'witness_script',
                'control_block',
                'leaf_version',
            ],
        )
        self.assertEqual(
            [
                event for event in events
                if event.get('step') == 'witness_script'
            ],
            [{
                'pc': -1,
                'opcode_name': 'witness_script',
                'phase': 'witnessScript',
                'step': 'witness_script',
                'script_hex': case.script.hex(),
                'stack_before': [],
                'stack_after': [],
                'committed': True,
                'executed': False,
            }],
        )


if __name__ == '__main__':
    unittest.main()
