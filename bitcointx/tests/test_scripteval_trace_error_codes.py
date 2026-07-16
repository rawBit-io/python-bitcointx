# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import pytest

from typing import Set, Tuple

from bitcointx.core import CTransaction, ValidationError
from bitcointx.core.script import (
    CScript,
    CScriptInvalidError,
    MAX_SCRIPT_SIZE,
    OP_1,
    OP_IF,
    OP_PUSHDATA1,
)
from bitcointx.core.scripteval import (
    EvalScript,
    EvalScriptError,
    VerifyScriptWithTrace,
    _TRACE_ERROR_CODE_MACHINE_NAMES,
    _trace_validation_error_identity,
)


FROZEN_TRACE_ERROR_CODES: Set[str] = {
    'BAD_OPCODE',
    'CLEANSTACK',
    'CLEANSTACK_REQUIRES_P2SH',
    'CLEANSTACK_REQUIRES_WITNESS',
    'DISCOURAGE_OP_SUCCESS',
    'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION',
    'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM',
    'EVAL_FALSE',
    'INVALID_SCRIPT_TYPE',
    'MISSING_SPENT_OUTPUTS',
    'PUSH_SIZE',
    'SCHNORR_SIG',
    'SCHNORR_SIG_HASHTYPE',
    'SCHNORR_SIG_SIZE',
    'SCRIPT_CLASS_MISMATCH',
    'SCRIPT_SIZE',
    'SIGHASH_ERROR',
    'SIG_PUSHONLY',
    'STACK_SIZE',
    'TAPROOT_WRONG_CONTROL_SIZE',
    'TWEAK_MISMATCH',
    'UNBALANCED_CONDITIONAL',
    'UNHANDLED_SCRIPT_VERIFY_FLAGS',
    'VALIDATION_ERROR',
    'WITNESS_MALLEATED',
    'WITNESS_MALLEATED_P2SH',
    'WITNESS_PROGRAM_MISMATCH',
    'WITNESS_PROGRAM_WITNESS_EMPTY',
    'WITNESS_PROGRAM_WRONG_LENGTH',
    'WITNESS_REQUIRES_P2SH',
    'WITNESS_UNEXPECTED',
}


STRUCTURAL_ERROR_CASES: Tuple[Tuple[CScript, str, str], ...] = (
    (
        CScript(bytes([int(OP_1)]) * (MAX_SCRIPT_SIZE + 1)),
        'script_size',
        'SCRIPT_SIZE',
    ),
    (
        CScript(bytes([int(OP_PUSHDATA1)])),
        'script_parse',
        'BAD_OPCODE',
    ),
    (
        CScript([OP_1, OP_IF, OP_1]),
        'conditional_balance',
        'UNBALANCED_CONDITIONAL',
    ),
)


def _eval_script_error(script: CScript) -> EvalScriptError:
    with pytest.raises(EvalScriptError) as exc_info:
        EvalScript([], script, CTransaction(), 0)
    return exc_info.value


def test_trace_error_code_vocabulary_is_frozen() -> None:
    assert set(_TRACE_ERROR_CODE_MACHINE_NAMES) == FROZEN_TRACE_ERROR_CODES


@pytest.mark.parametrize(
    ('script', 'machine_name', 'error_code'),
    STRUCTURAL_ERROR_CASES,
)
def test_eval_script_error_identity_survives_message_changes(
    script: CScript,
    machine_name: str,
    error_code: str,
) -> None:
    error = _eval_script_error(script)
    assert error.error_code == error_code

    error.args = ('deliberately reworded after construction',)
    assert _trace_validation_error_identity(error) == (
        machine_name,
        error_code,
    )


def test_cscript_invalid_error_has_structural_bad_opcode_identity() -> None:
    with pytest.raises(CScriptInvalidError) as exc_info:
        list(CScript(bytes([int(OP_PUSHDATA1)])).raw_iter())

    error = exc_info.value
    assert error.error_code == 'BAD_OPCODE'
    error.args = ('deliberately unrelated parse-error wording',)
    assert _trace_validation_error_identity(error) == (
        'script_parse',
        'BAD_OPCODE',
    )


@pytest.mark.parametrize(
    ('message', 'expected'),
    (
        ('legacy script too large wording', ('script_size', 'SCRIPT_SIZE')),
        ('legacy truncated data wording', ('script_parse', 'BAD_OPCODE')),
        (
            'legacy unterminated IF/ELSE block wording',
            ('conditional_balance', 'UNBALANCED_CONDITIONAL'),
        ),
        ('unclassified legacy failure', ('verification', 'VALIDATION_ERROR')),
    ),
)
def test_legacy_untagged_error_message_fallback(
    message: str,
    expected: Tuple[str, str],
) -> None:
    error = ValidationError(message)
    assert not hasattr(error, 'error_code')
    assert _trace_validation_error_identity(error) == expected


@pytest.mark.parametrize(
    ('script', 'machine_name', 'error_code'),
    STRUCTURAL_ERROR_CASES,
)
def test_structural_error_identities_are_emitted_end_to_end(
    script: CScript,
    machine_name: str,
    error_code: str,
) -> None:
    ok, steps, error = VerifyScriptWithTrace(
        CScript(),
        script,
        CTransaction(),
        0,
        flags=set(),
    )
    failures = [step for step in steps if step.get('failed') is True]

    assert ok is False
    assert error is not None
    assert len(failures) == 1
    assert failures[0] == steps[-1]
    assert failures[0]['step'] == machine_name
    assert failures[0]['opcode_name'] == machine_name
    assert failures[0]['error_code'] == error_code


def test_tapscript_missing_spent_outputs_emits_structural_code() -> None:
    # A well-formed signature inside a tapscript forces the sighash path,
    # which requires spent_outputs; without them the failing OP_CHECKSIG
    # step must carry the structural MISSING_SPENT_OUTPUTS code (this is
    # the sanctioned exception to "opcode failures have no error_code").
    from bitcointx.core.script import OP_CHECKSIG
    from bitcointx.tests.test_scripteval_policy_fixes import (
        TAPROOT_FLAGS,
        _make_tapscript_spend,
    )

    script = CScript(
        [b'\x22' * 32, OP_CHECKSIG], name='missing_prevouts_leaf'
    )
    script_pubkey, witness, _, spend = _make_tapscript_spend(
        script, 'missing_prevouts_leaf', [b'\x00' * 64]
    )

    ok, steps, error = VerifyScriptWithTrace(
        CScript(), script_pubkey, spend, 0,
        flags=TAPROOT_FLAGS, witness=witness, spent_outputs=None,
    )
    failures = [step for step in steps if step.get('failed') is True]

    assert ok is False
    assert error is not None
    assert 'spent_outputs are required' in error
    assert len(failures) == 1
    assert failures[0] == steps[-1]
    assert failures[0]['opcode_name'] == 'OP_CHECKSIG'
    assert failures[0]['error_code'] == 'MISSING_SPENT_OUTPUTS'
