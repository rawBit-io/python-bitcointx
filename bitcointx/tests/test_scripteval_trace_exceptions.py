# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import unittest

from unittest.mock import patch

from bitcointx.core import (
    COutPoint, CTransaction, CTxIn, CTxOut, ValidationError,
)
from bitcointx.core.script import (
    CScript, OP_0, OP_1, OP_CHECKSIG, OP_VERIFY,
)
from bitcointx.core.scripteval import VerifyScript, VerifyScriptWithTrace


class TestScriptEvaluationTraceExceptions(unittest.TestCase):

    @staticmethod
    def _dummy_transaction() -> CTransaction:
        return CTransaction(
            [CTxIn(COutPoint(b'\x01' * 32, 0))],
            [CTxOut(0, CScript([OP_1]))],
        )

    def test_runtime_error_from_sighash_propagates_unchanged(self) -> None:
        class VerificationInterrupted(RuntimeError):
            pass

        interruption = VerificationInterrupted('verification interrupted')
        script_sig = CScript([b'\x01', b'\x02'])
        script_pubkey = CScript([OP_CHECKSIG])

        with patch.object(
            type(script_pubkey), 'raw_sighash', side_effect=interruption,
        ):
            with self.assertRaises(VerificationInterrupted) as raised:
                VerifyScriptWithTrace(
                    script_sig,
                    script_pubkey,
                    self._dummy_transaction(),
                    0,
                    flags=set(),
                )

        self.assertIs(raised.exception, interruption)

    def test_validation_error_returns_false_tuple(self) -> None:
        script_pubkey = CScript([OP_0, OP_VERIFY])
        transaction = self._dummy_transaction()

        with self.assertRaises(ValidationError):
            VerifyScript(
                CScript(), script_pubkey, transaction, 0, flags=set(),
            )

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction, 0, flags=set(),
        )

        self.assertFalse(is_valid)
        self.assertEqual(len(steps), 2)
        self.assertIn('OP_VERIFY failed', error or '')

    def test_truncated_script_pubkey_returns_false_tuple(self) -> None:
        script_pubkey = CScript(b'\x02\x01')
        transaction = self._dummy_transaction()

        with self.assertRaises(ValidationError):
            VerifyScript(
                CScript(), script_pubkey, transaction, 0, flags=set(),
            )

        is_valid, steps, error = VerifyScriptWithTrace(
            CScript(), script_pubkey, transaction, 0, flags=set(),
        )

        self.assertFalse(is_valid)
        self.assertEqual(len(steps), 1)
        self.assertTrue(steps[0]['failed'])
        self.assertEqual(steps[0]['error_code'], 'BAD_OPCODE')
        self.assertEqual(steps[0]['phase'], 'scriptPubKey')
        self.assertIn('truncated data', error or '')

    def test_verdict_parity_for_valid_and_validation_invalid_inputs(
        self,
    ) -> None:
        transaction = self._dummy_transaction()
        cases = (
            ('valid', CScript([OP_1]), True),
            ('invalid', CScript([OP_0]), False),
        )

        for name, script_pubkey, expected_valid in cases:
            with self.subTest(name=name):
                try:
                    VerifyScript(
                        CScript(), script_pubkey, transaction, 0, flags=set(),
                    )
                except ValidationError:
                    untraced_valid = False
                else:
                    untraced_valid = True

                traced_valid, _steps, error = VerifyScriptWithTrace(
                    CScript(), script_pubkey, transaction, 0, flags=set(),
                )

                self.assertEqual(untraced_valid, expected_valid)
                self.assertEqual(traced_valid, untraced_valid)
                self.assertEqual(error is None, expected_valid)


if __name__ == '__main__':
    unittest.main()
