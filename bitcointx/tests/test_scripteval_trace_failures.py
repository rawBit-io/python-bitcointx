# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import hashlib

import pytest

from typing import (
    Dict, List, NamedTuple, Optional, Sequence, Set, Tuple,
)

from bitcointx.core import (
    COutPoint, CTransaction, CTxIn, CTxOut, ValidationError,
)
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    MAX_SCRIPT_SIZE,
    OP_0,
    OP_1,
    OP_2,
    OP_DROP,
    OP_DUP,
    OP_IF,
    OP_PUSHDATA1,
    OP_RESERVED,
    TaprootScriptTree,
)
from bitcointx.core.scripteval import (
    MAX_STACK_ITEMS,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_SIGPUSHONLY,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    ScriptVerifyFlag_Type,
    TraceStep,
    VerifyWitnessProgram,
    VerifyScriptWithTrace,
)
from bitcointx.wallet import CCoinKey, P2TRCoinAddress


AMOUNT = 100_000
VISIBLE_FAILURE_PHASES = {
    'scriptSig',
    'scriptPubKey',
    'redeemScript',
    'witnessScript',
    'taproot',
}
TAPROOT_FLAGS = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
}

TraceResult = Tuple[bool, List[TraceStep], Optional[str]]


class ScriptPathSpend(NamedTuple):
    script_pubkey: CScript
    script: CScript
    control: bytes
    witness: CScriptWitness
    transaction: CTransaction
    spent_outputs: Tuple[CTxOut, ...]


def _transaction(
    script_pubkey: CScript,
    script_sig: CScript = CScript(),
) -> Tuple[CTransaction, Tuple[CTxOut, ...]]:
    spent_outputs = (CTxOut(AMOUNT, script_pubkey),)
    transaction = CTransaction(
        [
            CTxIn(
                COutPoint(b'\x71' * 32, 0),
                script_sig,
                nSequence=0xFFFFFFFE,
            ),
        ],
        [CTxOut(AMOUNT - 1_000, CScript([OP_1]))],
        nVersion=2,
    )
    return transaction, spent_outputs


def _trace(
    script_pubkey: CScript,
    *,
    script_sig: CScript = CScript(),
    witness: Optional[CScriptWitness] = None,
    flags: Optional[Set[ScriptVerifyFlag_Type]] = None,
    provide_spent_outputs: bool = False,
    max_trace_steps: Optional[int] = 20_000,
    max_trace_bytes: Optional[int] = 25_000_000,
) -> TraceResult:
    transaction, spent_outputs = _transaction(script_pubkey, script_sig)
    return VerifyScriptWithTrace(
        script_sig,
        script_pubkey,
        transaction,
        0,
        flags=flags,
        amount=AMOUNT,
        witness=witness,
        spent_outputs=spent_outputs if provide_spent_outputs else None,
        max_trace_steps=max_trace_steps,
        max_trace_bytes=max_trace_bytes,
    )


def _p2wsh(
    script: CScript,
    stack: Sequence[bytes] = (),
) -> Tuple[CScript, CScriptWitness]:
    program = hashlib.sha256(bytes(script)).digest()
    return (
        CScript([OP_0, program]),
        CScriptWitness(list(stack) + [bytes(script)]),
    )


def _script_path_spend(
    script: CScript,
    *,
    leaf_version: Optional[int] = None,
    stack: Sequence[bytes] = (),
    control_transform: Optional[bytes] = None,
    output_program: Optional[bytes] = None,
) -> ScriptPathSpend:
    internal_key = CCoinKey.from_secret_bytes(b'\x41' * 32)
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
    script_and_control = tree.get_script_with_control_block(
        script.name or ''
    )
    assert script_and_control is not None
    committed_script, original_control = script_and_control
    control = (
        bytes(original_control)
        if control_transform is None
        else control_transform
    )
    if output_program is None:
        script_pubkey = P2TRCoinAddress.from_script_tree(
            tree
        ).to_scriptPubKey()
    else:
        script_pubkey = CScript([OP_1, output_program])
    transaction, spent_outputs = _transaction(script_pubkey)
    witness = CScriptWitness(
        list(stack) + [bytes(committed_script), control]
    )
    return ScriptPathSpend(
        script_pubkey=script_pubkey,
        script=committed_script,
        control=control,
        witness=witness,
        transaction=transaction,
        spent_outputs=spent_outputs,
    )


def _trace_script_path(
    spend: ScriptPathSpend,
    flags: Set[ScriptVerifyFlag_Type] = TAPROOT_FLAGS,
) -> TraceResult:
    return VerifyScriptWithTrace(
        CScript(),
        spend.script_pubkey,
        spend.transaction,
        0,
        flags=flags,
        amount=AMOUNT,
        witness=spend.witness,
        spent_outputs=spend.spent_outputs,
    )


def _assert_terminal_failure(
    result: TraceResult,
    error_code: str,
    context: str,
    *,
    step: Optional[str] = None,
    opcode_name: Optional[str] = None,
) -> Dict[str, object]:
    ok, typed_steps, error = result
    steps: List[Dict[str, object]] = [dict(item) for item in typed_steps]
    failures = [item for item in steps if item.get('failed') is True]

    assert ok is False, context
    assert error is not None, context
    assert len(failures) == 1, (context, failures)
    failure = failures[0]
    assert steps[-1] == failure, context
    assert failure['pc'] == -1, context
    assert failure['kind'] == 'validator', context
    assert failure['failed'] is True, context
    assert failure['error'] == error, context
    assert failure['error_code'] == error_code, context
    assert failure['phase'] in VISIBLE_FAILURE_PHASES, context
    assert failure['phase'] != 'witness', context
    assert isinstance(failure['stack_before'], list), context
    assert isinstance(failure['stack_after'], list), context
    assert isinstance(failure['step'], str), context
    assert isinstance(failure['opcode_name'], str), context
    if step is None:
        assert failure['step'] == failure['opcode_name'], context
    else:
        assert failure['step'] == step, context
    if opcode_name is not None:
        assert failure['opcode_name'] == opcode_name, context
    assert all('error_code' not in item for item in steps[:-1]), context
    return failure


def test_v0_witness_program_boundary_failures_are_terminal() -> None:
    witness_script = CScript([OP_1])
    correct_program = hashlib.sha256(bytes(witness_script)).digest()
    corrupted_program = bytes([correct_program[0] ^ 1]) + correct_program[1:]
    cases = (
        (
            'empty witness',
            _trace(
                CScript([OP_0, correct_program]),
                witness=CScriptWitness(),
            ),
            'WITNESS_PROGRAM_WITNESS_EMPTY',
            None,
        ),
        (
            'wrong v0 program length',
            _trace(
                CScript([OP_0, b'\x01' * 21]),
                witness=CScriptWitness([b'item']),
            ),
            'WITNESS_PROGRAM_WRONG_LENGTH',
            None,
        ),
        (
            'P2WPKH item count',
            _trace(
                CScript([OP_0, b'\x02' * 20]),
                witness=CScriptWitness([b'one item']),
            ),
            'WITNESS_PROGRAM_MISMATCH',
            None,
        ),
        (
            'P2WSH commitment mismatch',
            _trace(
                CScript([OP_0, corrupted_program]),
                witness=CScriptWitness([bytes(witness_script)]),
            ),
            'WITNESS_PROGRAM_MISMATCH',
            'witness_script_check',
        ),
    )

    for name, result, error_code, step in cases:
        _assert_terminal_failure(
            result,
            error_code,
            name,
            step=step,
            opcode_name=step,
        )


def test_taproot_witness_limits_are_terminal() -> None:
    element_spend = _script_path_spend(
        CScript([OP_1], name='large_element'),
        stack=[b'\x01' * 521],
    )
    stack_spend = _script_path_spend(
        CScript([OP_1], name='large_stack'),
        stack=[b''] * (MAX_STACK_ITEMS + 1),
    )

    _assert_terminal_failure(
        _trace_script_path(element_spend),
        'PUSH_SIZE',
        'taproot witness element limit',
    )
    _assert_terminal_failure(
        _trace_script_path(stack_spend),
        'STACK_SIZE',
        'taproot witness stack limit',
    )


def test_taproot_control_block_failures_are_terminal() -> None:
    leaf = CScript([OP_1], name='control_leaf')
    valid = _script_path_spend(leaf)
    wrong_size = ScriptPathSpend(
        script_pubkey=valid.script_pubkey,
        script=valid.script,
        control=valid.control[:-1],
        witness=CScriptWitness([bytes(valid.script), valid.control[:-1]]),
        transaction=valid.transaction,
        spent_outputs=valid.spent_outputs,
    )
    invalid_internal_control = (
        valid.control[:1] + b'\xff' * 32 + valid.control[33:]
    )
    invalid_internal = ScriptPathSpend(
        script_pubkey=valid.script_pubkey,
        script=valid.script,
        control=invalid_internal_control,
        witness=CScriptWitness([
            bytes(valid.script), invalid_internal_control,
        ]),
        transaction=valid.transaction,
        spent_outputs=valid.spent_outputs,
    )
    invalid_output = _script_path_spend(
        CScript([OP_1], name='invalid_output'),
        output_program=b'\xff' * 32,
    )
    unrelated_key = CCoinKey.from_secret_bytes(b'\x42' * 32)
    tweak_mismatch = _script_path_spend(
        CScript([OP_1], name='tweak_mismatch'),
        output_program=bytes(unrelated_key.xonly_pub),
    )

    cases = (
        ('wrong control size', wrong_size, 'TAPROOT_WRONG_CONTROL_SIZE'),
        (
            'invalid internal key',
            invalid_internal,
            'WITNESS_PROGRAM_MISMATCH',
        ),
        (
            'invalid output key',
            invalid_output,
            'WITNESS_PROGRAM_MISMATCH',
        ),
        ('tweak mismatch', tweak_mismatch, 'TWEAK_MISMATCH'),
    )
    for name, spend, error_code in cases:
        _assert_terminal_failure(
            _trace_script_path(spend),
            error_code,
            name,
            step='control_block',
            opcode_name='taproot_control_block',
        )


def test_taproot_key_path_failures_are_terminal() -> None:
    key = CCoinKey.from_secret_bytes(b'\x51' * 32)
    script_pubkey = P2TRCoinAddress.from_xonly_pubkey(
        key.xonly_pub
    ).to_scriptPubKey()
    cases = (
        (
            'schnorr signature size',
            _trace(
                script_pubkey,
                witness=CScriptWitness([b'\x01' * 63]),
                flags=TAPROOT_FLAGS,
                provide_spent_outputs=True,
            ),
            'SCHNORR_SIG_SIZE',
            None,
            None,
        ),
        (
            'schnorr hashtype',
            _trace(
                script_pubkey,
                witness=CScriptWitness([b'\x01' * 64 + b'\x00']),
                flags=TAPROOT_FLAGS,
                provide_spent_outputs=True,
            ),
            'SCHNORR_SIG_HASHTYPE',
            None,
            None,
        ),
        (
            'missing spent outputs',
            _trace(
                script_pubkey,
                witness=CScriptWitness([b'\x01' * 64]),
                flags=TAPROOT_FLAGS,
                provide_spent_outputs=False,
            ),
            'MISSING_SPENT_OUTPUTS',
            None,
            None,
        ),
        (
            'schnorr verification',
            _trace(
                script_pubkey,
                witness=CScriptWitness([b'\x00' * 64]),
                flags=TAPROOT_FLAGS,
                provide_spent_outputs=True,
            ),
            'SCHNORR_SIG',
            'schnorr_verify',
            'taproot_schnorr_verify',
        ),
    )

    for name, result, error_code, step, opcode_name in cases:
        _assert_terminal_failure(
            result,
            error_code,
            name,
            step=step,
            opcode_name=opcode_name,
        )


def test_discouraged_upgrades_and_tapscript_parse_are_terminal() -> None:
    future_flags = {
        SCRIPT_VERIFY_P2SH,
        SCRIPT_VERIFY_WITNESS,
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    }
    unknown_leaf = _script_path_spend(
        CScript([OP_1], name='unknown_leaf'),
        leaf_version=0xc2,
        stack=[b'\xaa'],
    )
    unknown_leaf_flags = set(TAPROOT_FLAGS)
    unknown_leaf_flags.add(
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    )
    op_success = _script_path_spend(
        CScript(bytes([int(OP_RESERVED)]), name='op_success')
    )
    op_success_flags = set(TAPROOT_FLAGS)
    op_success_flags.add(SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)
    malformed = _script_path_spend(
        CScript(bytes([int(OP_PUSHDATA1)]), name='malformed')
    )
    cases = (
        (
            'future witness program',
            _trace(
                CScript([OP_2, b'\x61' * 32]),
                witness=CScriptWitness(),
                flags=future_flags,
            ),
            'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM',
            None,
            None,
        ),
        (
            'unknown taproot leaf',
            _trace_script_path(unknown_leaf, unknown_leaf_flags),
            'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION',
            'leaf_version',
            'taproot_leaf_version',
        ),
        (
            'discouraged OP_SUCCESS',
            _trace_script_path(op_success, op_success_flags),
            'DISCOURAGE_OP_SUCCESS',
            None,
            None,
        ),
        (
            'malformed tapscript pre-scan',
            _trace_script_path(malformed),
            'BAD_OPCODE',
            None,
            None,
        ),
    )

    for name, result, error_code, step, opcode_name in cases:
        _assert_terminal_failure(
            result,
            error_code,
            name,
            step=step,
            opcode_name=opcode_name,
        )


def test_witness_final_stack_failures_are_terminal() -> None:
    cases = (
        ('empty', CScript([OP_0, OP_DROP]), 'EVAL_FALSE'),
        ('extra', CScript([OP_1, OP_1]), 'CLEANSTACK'),
        ('false', CScript([OP_0]), 'EVAL_FALSE'),
    )
    for name, witness_script, error_code in cases:
        script_pubkey, witness = _p2wsh(witness_script)
        _assert_terminal_failure(
            _trace(script_pubkey, witness=witness),
            error_code,
            f'witness final stack {name}',
        )


def test_cleanstack_and_flag_dependency_failures_are_terminal() -> None:
    _assert_terminal_failure(
        _trace(
            CScript([OP_1, OP_1]),
            flags={
                SCRIPT_VERIFY_P2SH,
                SCRIPT_VERIFY_WITNESS,
                SCRIPT_VERIFY_CLEANSTACK,
            },
        ),
        'CLEANSTACK',
        'outer cleanstack',
    )
    _assert_terminal_failure(
        _trace(
            CScript([OP_1]),
            flags={SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_CLEANSTACK},
        ),
        'CLEANSTACK_REQUIRES_WITNESS',
        'CLEANSTACK requires WITNESS',
    )
    _assert_terminal_failure(
        _trace(
            CScript([OP_1]),
            flags={SCRIPT_VERIFY_WITNESS},
        ),
        'WITNESS_REQUIRES_P2SH',
        'WITNESS requires P2SH',
    )


def test_base_and_p2sh_boundary_failures_are_terminal() -> None:
    oversized = CScript(bytes([int(OP_1)]) * (MAX_SCRIPT_SIZE + 1))
    truncated = CScript(bytes([int(OP_PUSHDATA1)]))
    unbalanced = CScript([OP_1, OP_IF, OP_1])
    pushonly_script_sig = CScript([OP_1, OP_DROP])

    redeem_true = CScript([OP_1])
    nonpush_p2sh_sig = CScript([bytes(redeem_true), OP_DUP])
    p2sh_pubkey = redeem_true.to_p2sh_scriptPubKey()

    redeem_false = CScript([OP_0])
    p2sh_false_sig = CScript([bytes(redeem_false)])
    p2sh_false_pubkey = redeem_false.to_p2sh_scriptPubKey()

    cases = (
        (
            'script size',
            _trace(oversized),
            'SCRIPT_SIZE',
        ),
        (
            'truncated pushdata',
            _trace(truncated),
            'BAD_OPCODE',
        ),
        (
            'unbalanced conditional',
            _trace(unbalanced),
            'UNBALANCED_CONDITIONAL',
        ),
        (
            'SIGPUSHONLY precheck',
            _trace(
                CScript([OP_1]),
                script_sig=pushonly_script_sig,
                flags={SCRIPT_VERIFY_SIGPUSHONLY},
            ),
            'SIG_PUSHONLY',
        ),
        (
            'P2SH push-only boundary',
            _trace(
                p2sh_pubkey,
                script_sig=nonpush_p2sh_sig,
                flags={SCRIPT_VERIFY_P2SH},
            ),
            'SIG_PUSHONLY',
        ),
        (
            'P2SH redeemScript false',
            _trace(
                p2sh_false_pubkey,
                script_sig=p2sh_false_sig,
                flags={SCRIPT_VERIFY_P2SH},
            ),
            'EVAL_FALSE',
        ),
        (
            'unexpected witness',
            _trace(
                CScript([OP_1]),
                witness=CScriptWitness([b'unexpected']),
                flags={SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS},
            ),
            'WITNESS_UNEXPECTED',
        ),
    )

    for name, result, error_code in cases:
        _assert_terminal_failure(result, error_code, name)


def test_native_and_wrapped_witness_malleation_are_terminal() -> None:
    witness_script = CScript([OP_1])
    witness_program, witness = _p2wsh(witness_script)
    native_result = _trace(
        witness_program,
        script_sig=CScript([OP_1]),
        witness=witness,
        flags={SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS},
    )

    p2sh_pubkey = witness_program.to_p2sh_scriptPubKey()
    wrapped_result = _trace(
        p2sh_pubkey,
        script_sig=CScript([b'extra', bytes(witness_program)]),
        witness=witness,
        flags={SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS},
    )

    _assert_terminal_failure(
        native_result,
        'WITNESS_MALLEATED',
        'native witness scriptSig malleation',
    )
    _assert_terminal_failure(
        wrapped_result,
        'WITNESS_MALLEATED_P2SH',
        'wrapped witness scriptSig malleation',
    )


def test_opcode_failure_is_the_only_terminal_and_has_no_error_code() -> None:
    ok, typed_steps, error = _trace(CScript([OP_DROP]))
    steps: List[Dict[str, object]] = [dict(item) for item in typed_steps]
    failures = [item for item in steps if item.get('failed') is True]

    assert ok is False
    assert error is not None
    assert len(failures) == 1
    assert steps[-1] == failures[0]
    assert failures[0]['pc'] == 0
    assert failures[0]['opcode_name'] == 'OP_DROP'
    assert failures[0]['error'] == error
    assert 'kind' not in failures[0]
    assert 'error_code' not in failures[0]


def test_direct_witness_callback_does_not_duplicate_opcode_failure() -> None:
    script_pubkey, witness = _p2wsh(CScript([OP_DROP]))
    transaction, _ = _transaction(script_pubkey)
    typed_steps: List[TraceStep] = []

    with pytest.raises(ValidationError):
        VerifyWitnessProgram(
            witness,
            0,
            script_pubkey.witness_program(),
            transaction,
            0,
            flags={SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS},
            on_step=typed_steps.append,
        )

    steps: List[Dict[str, object]] = [dict(item) for item in typed_steps]
    failures = [item for item in steps if item.get('failed') is True]
    assert failures == [steps[-1]]
    assert failures[0]['opcode_name'] == 'OP_DROP'
    assert 'kind' not in failures[0]
    assert 'error_code' not in failures[0]


def test_trace_truncation_is_the_only_failure_invariant_exemption() -> None:
    ok, typed_steps, error = _trace(
        CScript([OP_0]),
        max_trace_steps=0,
        max_trace_bytes=None,
    )
    steps: List[Dict[str, object]] = [dict(item) for item in typed_steps]

    assert ok is False
    assert error == 'scriptPubKey returned false'
    assert [item.get('step') for item in steps] == ['trace_truncated']
    assert all(item.get('failed') is not True for item in steps)
    assert steps[-1]['phase'] == 'scriptPubKey'
