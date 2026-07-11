# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import hashlib
import unittest

from bitcointx.core import (
    COutPoint, CTransaction, CTxIn, CTxOut, ValidationError, x,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript, CScriptWitness, OP_0, OP_1, OP_CHECKSIG, OP_DUP,
    OP_EQUALVERIFY, OP_HASH160, OP_VERIFY, SIGHASH_ALL,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_P2SH, VerifyScript, VerifyScriptWithTrace,
)


class TestScriptEvaluationTrace(unittest.TestCase):

    @staticmethod
    def _dummy_transaction() -> CTransaction:
        return CTransaction(
            [CTxIn(COutPoint(b'\x01' * 32, 0))],
            [CTxOut(0, CScript([OP_1]))],
        )

    def test_bip143_native_p2wpkh_trace(self) -> None:
        unsigned_tx = x(
            '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf4'
            '33541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655'
            'c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff0'
            '2202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac'
            '7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50'
            'ce2f0167faa815988ac11000000'
        )
        signature = x(
            '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb'
            '1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d4'
            '3c212a8caed02de67eebee01'
        )
        pubkey = x(
            '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07'
            'aeee6357'
        )
        program = '1d0f172a0ecb48aee1be1f2687d2963ae33f71a1'
        script_pubkey = CScript(x('0014' + program))
        witness = CScriptWitness([signature, pubkey])
        transaction = CTransaction.deserialize(unsigned_tx)

        VerifyScript(
            CScript(), script_pubkey, transaction, 1,
            amount=600000000, witness=witness,
        )

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction,
            1, amount=600000000, witness=witness,
        )

        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertEqual(
            [(step['phase'], step.get('kind'), step.get('step'))
             for step in steps],
            [
                ('scriptPubKey', None, None),
                ('scriptPubKey', None, None),
                ('witness', 'validator', 'witness_program_match'),
                ('witness', 'validator', 'witness_load'),
                ('witness', 'validator', 'witness_load'),
                ('witness', 'validator', 'scriptcode_derive'),
                ('witnessScript', None, None),
                ('witnessScript', None, None),
                ('witnessScript', None, None),
                ('witnessScript', None, None),
                ('witnessScript', None, None),
            ],
        )

        signature_hex = signature.hex()
        pubkey_hex = pubkey.hex()
        opcode_steps = [step for step in steps if 'kind' not in step]
        self.assertEqual(
            [step['opcode_name'] for step in opcode_steps],
            [
                'OP_0', 'unknown opcode', 'OP_DUP', 'OP_HASH160',
                'unknown opcode', 'OP_EQUALVERIFY', 'OP_CHECKSIG',
            ],
        )
        self.assertEqual(
            [
                (
                    step['pc'], step['opcode'],
                    step['stack_before'], step['stack_after'],
                )
                for step in opcode_steps
            ],
            [
                (0, 0, [], ['']),
                (1, 20, [''], ['', program]),
                (
                    0, int(OP_DUP), [signature_hex, pubkey_hex],
                    [signature_hex, pubkey_hex, pubkey_hex],
                ),
                (
                    1, int(OP_HASH160),
                    [signature_hex, pubkey_hex, pubkey_hex],
                    [signature_hex, pubkey_hex, program],
                ),
                (
                    2, 20, [signature_hex, pubkey_hex, program],
                    [signature_hex, pubkey_hex, program, program],
                ),
                (
                    23, int(OP_EQUALVERIFY),
                    [signature_hex, pubkey_hex, program, program],
                    [signature_hex, pubkey_hex],
                ),
                (
                    24, int(OP_CHECKSIG), [signature_hex, pubkey_hex],
                    ['01'],
                ),
            ],
        )

        validator_steps = [
            step for step in steps if step.get('kind') == 'validator'
        ]
        self.assertTrue(
            all(step['pc'] == -1 for step in validator_steps)
        )
        match, load_signature, load_pubkey, derive = validator_steps
        self.assertEqual(match['program_hex'], program)
        self.assertEqual(match['witness_version'], 0)
        self.assertFalse(match['p2sh_wrapped'])
        self.assertEqual(match['stack_before'], [])
        self.assertEqual(match['stack_after'], [])

        self.assertEqual(
            (load_signature['witness_index'],
             load_signature['witness_total']),
            (0, 2),
        )
        self.assertEqual(load_signature['stack_before'], [])
        self.assertEqual(load_signature['stack_after'], [signature_hex])
        self.assertEqual(load_pubkey['witness_index'], 1)
        self.assertEqual(load_pubkey['stack_before'], [signature_hex])
        self.assertEqual(
            load_pubkey['stack_after'], [signature_hex, pubkey_hex]
        )

        script_code = '76a914' + program + '88ac'
        self.assertEqual(derive['script_hex'], script_code)
        self.assertEqual(derive['program_hex'], program)
        self.assertEqual(
            derive['stack_before'], [signature_hex, pubkey_hex]
        )
        self.assertEqual(derive['stack_after'], derive['stack_before'])

    def test_p2wsh_op_true_and_corrupted_program_traces(self) -> None:
        transaction = self._dummy_transaction()
        witness_script = CScript([OP_1])
        witness_script_hex = bytes(witness_script).hex()
        program = hashlib.sha256(witness_script).digest()
        witness = CScriptWitness([bytes(witness_script)])
        script_pubkey = CScript([OP_0, program])

        VerifyScript(
            CScript(), script_pubkey, transaction, 0, witness=witness,
        )

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction, 0,
            witness=witness,
        )

        self.assertTrue(is_valid)
        self.assertIsNone(error)
        validator_steps = [
            step for step in steps if step.get('kind') == 'validator'
        ]
        self.assertEqual(
            [step['step'] for step in validator_steps],
            [
                'witness_program_match', 'witness_load',
                'witness_script_check',
            ],
        )
        load_step, check_step = validator_steps[1:]
        self.assertEqual(load_step['stack_before'], [])
        self.assertEqual(load_step['stack_after'], [witness_script_hex])
        self.assertEqual(check_step['script_hex'], witness_script_hex)
        self.assertEqual(check_step['sha256_hex'], program.hex())
        self.assertEqual(check_step['program_hex'], program.hex())
        self.assertEqual(check_step['stack_before'], [witness_script_hex])
        self.assertEqual(check_step['stack_after'], [])
        self.assertEqual(steps[-1]['phase'], 'witnessScript')
        self.assertEqual(steps[-1]['opcode_name'], 'OP_1')
        self.assertEqual(steps[-1]['pc'], 0)
        self.assertEqual(steps[-1]['opcode'], int(OP_1))
        self.assertEqual(steps[-1]['stack_before'], [])
        self.assertEqual(steps[-1]['stack_after'], ['01'])

        corrupted_program = bytes([program[0] ^ 1]) + program[1:]
        corrupted_script_pubkey = CScript([OP_0, corrupted_program])
        with self.assertRaises(ValidationError):
            VerifyScript(
                CScript(), corrupted_script_pubkey, transaction, 0,
                witness=witness,
            )

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), corrupted_script_pubkey, transaction, 0,
            witness=witness,
        )

        self.assertFalse(is_valid)
        self.assertIn('witness program mismatch', error or '')
        validator_steps = [
            step for step in steps if step.get('kind') == 'validator'
        ]
        self.assertEqual(
            [step['step'] for step in validator_steps],
            [
                'witness_program_match', 'witness_load',
                'witness_script_check',
            ],
        )
        failed_check = validator_steps[-1]
        self.assertTrue(failed_check['failed'])
        self.assertEqual(failed_check['error'], 'witness program mismatch')
        self.assertEqual(failed_check['sha256_hex'], program.hex())
        self.assertEqual(failed_check['program_hex'], corrupted_program.hex())
        self.assertEqual(failed_check['stack_before'], [witness_script_hex])
        self.assertEqual(failed_check['stack_after'], [])

    def test_witness_load_precedes_p2wpkh_item_count_check(self) -> None:
        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), CScript([OP_0, b'\x01' * 20]),
            self._dummy_transaction(), 0,
            witness=CScriptWitness([b'only one item']),
        )

        self.assertFalse(is_valid)
        self.assertIn('witness program mismatch', error or '')
        self.assertEqual(
            [step.get('step') for step in steps if 'kind' in step],
            ['witness_program_match', 'witness_load'],
        )

    def test_p2sh_wrapped_witness_marks_validator_step(self) -> None:
        transaction = self._dummy_transaction()
        witness_script = CScript([OP_1])
        witness_program = CScript([
            OP_0, hashlib.sha256(witness_script).digest(),
        ])

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript([bytes(witness_program)]),
            witness_program.to_p2sh_scriptPubKey(),
            transaction,
            0,
            witness=CScriptWitness([bytes(witness_script)]),
        )

        self.assertTrue(is_valid)
        self.assertIsNone(error)
        match = next(
            step for step in steps
            if step.get('step') == 'witness_program_match'
        )
        self.assertTrue(match['p2sh_wrapped'])
        self.assertIn('redeemScript', [step['phase'] for step in steps])
        self.assertEqual(steps[-1]['phase'], 'witnessScript')

    def test_legacy_p2pkh_and_p2sh_traces_have_only_opcodes(self) -> None:
        transaction = self._dummy_transaction()
        key = CKey.from_secret_bytes(b'\x02' * 32)
        p2pkh_script = CScript([
            OP_DUP, OP_HASH160, key.pub.key_id, OP_EQUALVERIFY, OP_CHECKSIG,
        ])
        signature = (
            key.sign(p2pkh_script.sighash(transaction, 0, SIGHASH_ALL))
            + bytes([SIGHASH_ALL])
        )
        script_sig = CScript([signature, key.pub])

        VerifyScript(script_sig, p2pkh_script, transaction, 0)
        is_valid, steps, error = VerifyScriptWithTrace(
            script_sig, p2pkh_script, transaction, 0,
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertTrue(all('kind' not in step for step in steps))
        self.assertEqual(
            [step['phase'] for step in steps],
            ['scriptSig'] * 2 + ['scriptPubKey'] * 5,
        )

        redeem_script = CScript([OP_1])
        script_sig = CScript([bytes(redeem_script)])
        p2sh_script = redeem_script.to_p2sh_scriptPubKey()
        flags = {SCRIPT_VERIFY_P2SH}

        VerifyScript(script_sig, p2sh_script, transaction, 0, flags=flags)
        is_valid, steps, error = VerifyScriptWithTrace(
            script_sig, p2sh_script, transaction, 0, flags=flags,
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertTrue(all('kind' not in step for step in steps))
        self.assertEqual(
            [step['phase'] for step in steps],
            [
                'scriptSig', 'scriptPubKey', 'scriptPubKey',
                'scriptPubKey', 'redeemScript',
            ],
        )

    def test_failed_opcode_is_emitted_before_error(self) -> None:
        transaction = self._dummy_transaction()
        failing_script = CScript([OP_0, OP_VERIFY])

        with self.assertRaises(ValidationError):
            VerifyScript(CScript(), failing_script, transaction, 0)

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), failing_script, transaction, 0,
        )

        self.assertFalse(is_valid)
        self.assertIn('OP_VERIFY failed', error or '')
        self.assertEqual(len(steps), 2)
        self.assertNotIn('failed', steps[0])
        self.assertTrue(steps[1]['failed'])
        self.assertIn('OP_VERIFY failed', steps[1]['error'])
        self.assertEqual(steps[1]['stack_before'], [''])
        self.assertEqual(steps[1]['stack_after'], [''])


if __name__ == '__main__':
    unittest.main()
