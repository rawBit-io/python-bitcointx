# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import unittest

from typing import List, Optional, Tuple

from bitcointx.core import COutPoint, CTransaction, CTxIn, CTxOut
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript, CScriptWitness, OP_1, TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    TraceStep,
    VerifyScriptWithTrace,
)
from bitcointx.wallet import P2TRCoinAddress


TAPROOT_FLAGS = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
}


def _unknown_leaf_spend(
) -> Tuple[CScript, CScriptWitness, CTransaction]:
    key = CKey.from_secret_bytes(b'\x23' * 32)
    script = CScript([OP_1], name='future_leaf')
    tree = TaprootScriptTree(
        [script],
        internal_pubkey=key.xonly_pub,
        leaf_version=0xc2,
    )
    script_and_control = tree.get_script_with_control_block('future_leaf')
    assert script_and_control is not None
    committed_script, control = script_and_control

    script_pubkey = P2TRCoinAddress.from_script_tree(tree).to_scriptPubKey()
    witness = CScriptWitness([b'\xaa', committed_script, control])
    transaction = CTransaction(
        [CTxIn(COutPoint(b'\x01' * 32, 0))],
        [CTxOut(0, CScript([OP_1]))],
    )
    return script_pubkey, witness, transaction


class TestUnknownTaprootLeafVersionTrace(unittest.TestCase):

    def _verify(self, *, reject: bool) -> Tuple[
        bool, List[TraceStep], Optional[str],
    ]:
        script_pubkey, witness, transaction = _unknown_leaf_spend()
        flags = set(TAPROOT_FLAGS)
        if reject:
            flags.add(
                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
            )
        return VerifyScriptWithTrace(
            CScript(),
            script_pubkey,
            transaction,
            0,
            flags=flags,
            witness=witness,
        )

    def _assert_unchanged_taproot_prefix(
        self, steps: List[TraceStep],
    ) -> None:
        self.assertEqual(
            [step.get('step') for step in steps[-4:]],
            [
                'witness_stack',
                'witness_script',
                'control_block',
                'leaf_version',
            ],
        )
        self.assertTrue(
            all('kind' not in step for step in steps[-4:-1])
        )

    def test_unknown_leaf_version_skip_event_has_full_schema(self) -> None:
        is_valid, steps, error = self._verify(reject=False)

        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self._assert_unchanged_taproot_prefix(steps)
        self.assertEqual(
            [step for step in steps if step.get('step') == 'leaf_version'],
            [{
                'pc': -1,
                'kind': 'validator',
                'opcode_name': 'taproot_leaf_version',
                'step': 'leaf_version',
                'phase': 'taproot',
                'leaf_version': 0xc2,
                'policy': 'skip',
                'stack_before': ['aa'],
                'stack_after': ['aa'],
            }],
        )

    def test_unknown_leaf_version_reject_event_has_full_schema(self) -> None:
        is_valid, steps, error = self._verify(reject=True)

        self.assertFalse(is_valid)
        self.assertEqual(error, 'taproot leaf version not supported')
        self._assert_unchanged_taproot_prefix(steps)
        self.assertEqual(
            [step for step in steps if step.get('step') == 'leaf_version'],
            [{
                'pc': -1,
                'kind': 'validator',
                'opcode_name': 'taproot_leaf_version',
                'step': 'leaf_version',
                'phase': 'taproot',
                'leaf_version': 0xc2,
                'policy': 'reject',
                'stack_before': ['aa'],
                'stack_after': ['aa'],
                'failed': True,
                'error': 'taproot leaf version not supported',
                'error_code': 'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION',
            }],
        )


if __name__ == '__main__':
    unittest.main()
