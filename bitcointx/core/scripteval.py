# Copyright (C) 2012-2017 The python-bitcoinlib developers
# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501,C901

"""Script evaluation

Be warned that there are highly likely to be consensus bugs in this code; it is
unlikely to match Satoshi Bitcoin exactly. Think carefully before using this
module.
"""

import hashlib
from io import BytesIO
from typing import (
    Iterable, Optional, List, Tuple, Set, Sequence, Type, TypeVar, Union,
    Callable, TypedDict
)

import bitcointx.core
import bitcointx.core._bignum
import bitcointx.core.key
import bitcointx.core.serialize
from bitcointx.core.serialize import BytesSerializer, VarIntSerializer
import bitcointx.core._ripemd160

from bitcointx.util import ensure_isinstance

from bitcointx.core.script import (
    # Script helpers & containers
    CScript, CScriptOp, CScriptWitness, CScriptInvalidError,
    OPCODE_NAMES, DISABLED_OPCODES,
    FindAndDelete, IsLowDERSignature,
    SignatureHashSchnorr,
    SIGVERSION_Type, SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
    SIGVERSION_TAPROOT, SIGVERSION_TAPSCRIPT,

    # SIGHASH flags
    SIGHASH_Type,
    SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,

    # Size / opcode limits
    MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_OPCODES, MAX_SCRIPT_SIZE,

    # Signature opcodes
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,

    # Arithmetic & logic
    OP_1ADD, OP_1SUB, OP_1NEGATE, OP_NEGATE, OP_ABS, OP_ADD, OP_SUB,
    OP_BOOLAND, OP_BOOLOR, OP_NOT, OP_0NOTEQUAL,
    OP_EQUAL, OP_EQUALVERIFY,
    OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_LESSTHAN, OP_LESSTHANOREQUAL,
    OP_NUMNOTEQUAL, OP_GREATERTHAN, OP_GREATERTHANOREQUAL,
    OP_MIN, OP_MAX, OP_WITHIN,

    # Constants / pushdata
    OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9,
    OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,

    # Flow-control
    OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN,

    # Stack manipulation
    OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT,
    OP_SWAP, OP_TUCK,
    OP_TOALTSTACK, OP_FROMALTSTACK, OP_DEPTH, OP_IFDUP,
    OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP,

    # Crypto / hashing
    OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256,

    # Misc / NOP family
    OP_SIZE,
    OP_NOP, OP_NOP1, OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5,
    OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10,
    OP_CODESEPARATOR,

    # Lock-time & sequence
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
)

T_EvalScriptError = TypeVar('T_EvalScriptError', bound='EvalScriptError')

MAX_NUM_SIZE = 4
MAX_STACK_ITEMS = 1000
ANNEX_TAG = 0x50
VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50
VALIDATION_WEIGHT_OFFSET = 50
WITNESS_V1_TAPROOT_SIZE = 32
VALID_SCHNORR_HASHTYPES = {1, 2, 3, 0x81, 0x82, 0x83}
TAPROOT_LEAF_MASK = 0xfe
TAPROOT_LEAF_TAPSCRIPT = 0xc0
TAPROOT_CONTROL_BASE_SIZE = 33
TAPROOT_CONTROL_NODE_SIZE = 32
TAPROOT_CONTROL_MAX_NODE_COUNT = 128
TAPROOT_CONTROL_MAX_SIZE = (
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT
)

# --- RAWBIT PATCH START: CLTV/CSV constants ----------------------------
# These are used by _CheckLockTimeVerify / _CheckSequenceVerify
LOCKTIME_THRESHOLD            = 500000000      #  < → block-height, ≥ → unix time
SEQUENCE_LOCKTIME_MASK        = 0x0000FFFF
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31      # 0x80000000
SEQUENCE_LOCKTIME_TYPE_FLAG    = 1 << 22      # 0x00400000
# --- RAWBIT PATCH END ---------------------------------------------------

class ScriptVerifyFlag_Type:
    ...


SCRIPT_VERIFY_P2SH = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_STRICTENC = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_DERSIG = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_LOW_S = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_NULLDUMMY = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_SIGPUSHONLY = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_MINIMALDATA = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_CLEANSTACK = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_MINIMALIF = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_NULLFAIL = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_WITNESS = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_CONST_SCRIPTCODE = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_TAPROOT = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = ScriptVerifyFlag_Type()
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = ScriptVerifyFlag_Type()

_STRICT_ENCODING_FLAGS = set((SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_LOW_S, SCRIPT_VERIFY_STRICTENC))

# --- RAWBIT PATCH START: we handle CLTV/CSV, so they are not "unhandled"
UNHANDLED_SCRIPT_VERIFY_FLAGS = set((
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
))
# --- RAWBIT PATCH END ---------------------------------------------------

MANDATORY_SCRIPT_VERIFY_FLAGS = {SCRIPT_VERIFY_P2SH}

STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS | {
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_STRICTENC,
    SCRIPT_VERIFY_MINIMALDATA,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_MINIMALIF,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_LOW_S,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
}

ALL_SCRIPT_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | {
    SCRIPT_VERIFY_SIGPUSHONLY
}

SCRIPT_VERIFY_FLAGS_BY_NAME = {
    'P2SH': SCRIPT_VERIFY_P2SH,
    'STRICTENC': SCRIPT_VERIFY_STRICTENC,
    'DERSIG': SCRIPT_VERIFY_DERSIG,
    'LOW_S': SCRIPT_VERIFY_LOW_S,
    'NULLDUMMY': SCRIPT_VERIFY_NULLDUMMY,
    'SIGPUSHONLY': SCRIPT_VERIFY_SIGPUSHONLY,
    'MINIMALDATA': SCRIPT_VERIFY_MINIMALDATA,
    'DISCOURAGE_UPGRADABLE_NOPS': SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    'CLEANSTACK': SCRIPT_VERIFY_CLEANSTACK,
    'CHECKLOCKTIMEVERIFY': SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    'CHECKSEQUENCEVERIFY': SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    'MINIMALIF': SCRIPT_VERIFY_MINIMALIF,
    'NULLFAIL': SCRIPT_VERIFY_NULLFAIL,
    'WITNESS': SCRIPT_VERIFY_WITNESS,
    'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM': SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    'WITNESS_PUBKEYTYPE': SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    'CONST_SCRIPTCODE': SCRIPT_VERIFY_CONST_SCRIPTCODE,
    # --- RAWBIT PATCH: completeness
    'TAPROOT': SCRIPT_VERIFY_TAPROOT,
    'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION': SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    'DISCOURAGE_OP_SUCCESS': SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    'DISCOURAGE_UPGRADABLE_PUBKEYTYPE': SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
}

SCRIPT_VERIFY_FLAGS_NAMES = {v: k for k, v in SCRIPT_VERIFY_FLAGS_BY_NAME.items()}


def _opcode_name(sop: Optional[CScriptOp]) -> str:
    if sop is None:
        return 'unspecified opcode'
    return OPCODE_NAMES.get(sop, 'unknown opcode')


class ScriptEvalState:
    __slots__: List[str] = ['sop', 'sop_data', 'sop_pc', 'stack', 'scriptIn',
                            'txTo', 'inIdx', 'flags', 'altstack', 'vfExec',
                            'pbegincodehash', 'nOpCount']

    def __init__(self, *,
                 sop: Optional[CScriptOp] = None,
                 sop_data: Optional[bytes] = None,
                 sop_pc: Optional[int] = None,
                 stack: Optional[List[bytes]] = None,
                 scriptIn: Optional[CScript] = None,
                 txTo: Optional['bitcointx.core.CTransaction'] = None,
                 inIdx: Optional[int] = None,
                 flags: Optional[Set[ScriptVerifyFlag_Type]] = None,
                 altstack: Optional[List[bytes]] = None,
                 vfExec: Optional[List[bool]] = None,
                 pbegincodehash: Optional[int] = None,
                 nOpCount: Optional[int] = None):
        self.sop = sop
        self.sop_data = sop_data
        self.sop_pc = sop_pc
        self.stack = stack
        self.scriptIn = scriptIn
        self.txTo = txTo
        self.inIdx = inIdx
        self.flags = flags
        self.altstack = altstack
        self.vfExec = vfExec
        self.pbegincodehash = pbegincodehash
        self.nOpCount = nOpCount


class ScriptExecutionData:
    __slots__ = [
        'tapleaf_hash', 'tapleaf_hash_init',
        'codeseparator_pos', 'codeseparator_pos_init',
        'annex_hash', 'annex_present', 'annex_init',
        'validation_weight_left', 'validation_weight_left_init',
    ]

    def __init__(self) -> None:
        self.tapleaf_hash: Optional[bytes] = None
        self.tapleaf_hash_init: bool = False
        self.codeseparator_pos: int = 0xFFFFFFFF
        self.codeseparator_pos_init: bool = False
        self.annex_hash: Optional[bytes] = None
        self.annex_present: bool = False
        self.annex_init: bool = False
        self.validation_weight_left: int = 0
        self.validation_weight_left_init: bool = False


def script_verify_flags_to_string(flags: Iterable[ScriptVerifyFlag_Type]) -> str:
    return ",".join(SCRIPT_VERIFY_FLAGS_NAMES[f] for f in flags)


class EvalScriptError(bitcointx.core.ValidationError):
    """Base class for exceptions raised when a script fails during EvalScript()

    The execution state just prior the opcode raising the is saved. (if
    available)
    """

    def __init__(self, msg: str, state: ScriptEvalState) -> None:
        super().__init__('EvalScript: %s' % msg)
        self.state = state


class MaxOpCountError(EvalScriptError):
    def __init__(self, state: ScriptEvalState) -> None:
        super().__init__('max opcode count exceeded', state)


class MissingOpArgumentsError(EvalScriptError):
    """Missing arguments"""
    def __init__(self, state: ScriptEvalState, *, expected_stack_depth: int
                 ) -> None:
        n_items = '?' if state.stack is None else f'{len(state.stack)}'
        super().__init__((f'missing arguments for {_opcode_name(state.sop)}; '
                          f'need {expected_stack_depth} items, '
                          f'but only {n_items} on stack'),
                         state)


class ArgumentsInvalidError(EvalScriptError):
    """Arguments are invalid"""
    def __init__(self, msg: Optional[str], state: ScriptEvalState
                 ) -> None:
        super().__init__(f'{_opcode_name(state.sop)} args invalid: {msg}',
                         state)


class VerifyOpFailedError(EvalScriptError):
    """A VERIFY opcode failed"""
    def __init__(self, state: ScriptEvalState) -> None:
        super().__init__(f'{_opcode_name(state.sop)} failed', state)


# A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
# Where R and S are not negative (their first byte has its highest bit not set), and not
# excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
# in which case a single 0 byte is necessary and even required).
#
# See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
#
# This function is consensus-critical since BIP66.
#
# ported from bitcoind's src/script/interpreter.cpp
#
def _IsValidSignatureEncoding(sig: bytes) -> bool:  # noqa
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    # * total-length: 1-byte length descriptor of everything that follows,
    #   excluding the sighash byte.
    # * R-length: 1-byte length descriptor of the R value that follows.
    # * R: arbitrary-length big-endian encoded R value. It must use the shortest
    #   possible encoding for a positive integers (which means no null bytes at
    #   the start, except a single one when the next byte has its highest bit set).
    # * S-length: 1-byte length descriptor of the S value that follows.
    # * S: arbitrary-length big-endian encoded S value. The same rules apply.
    # * sighash: 1-byte value indicating what data is hashed (not part of the DER
    #   signature)

    # Minimum and maximum size constraints.
    if (len(sig) < 9):
        return False

    if len(sig) > 73:
        return False

    # A signature is of type 0x30 (compound).
    if sig[0] != 0x30:
        return False

    # Make sure the length covers the entire signature.
    if sig[1] != len(sig) - 3:
        return False

    # Extract the length of the R element.
    lenR = sig[3]

    # Make sure the length of the S element is still inside the signature.
    if 5 + lenR >= len(sig):
        return False

    # Extract the length of the S element.
    lenS = sig[5 + lenR]

    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    if (lenR + lenS + 7) != len(sig):
        return False

    # Check whether the R element is an integer.
    if sig[2] != 0x02:
        return False

    # Zero-length integers are not allowed for R.
    if lenR == 0:
        return False

    # Negative numbers are not allowed for R.
    if sig[4] & 0x80:
        return False

    # Null bytes at the start of R are not allowed, unless R would
    # otherwise be interpreted as a negative number.
    if lenR > 1 and sig[4] == 0x00 and (sig[5] & 0x80) == 0:
        return False

    # Check whether the S element is an integer.
    if sig[lenR + 4] != 0x02:
        return False

    # Zero-length integers are not allowed for S.
    if lenS == 0:
        return False

    # Negative numbers are not allowed for S.
    if sig[lenR + 6] & 0x80:
        return False

    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if lenS > 1 and sig[lenR + 6] == 0x00 and (not (sig[lenR + 7] & 0x80)):
        return False

    return True


def _IsCompressedOrUncompressedPubKey(pubkey: bytes) -> bool:
    if len(pubkey) < 33:
        #  Non-canonical public key: too short
        return False

    if pubkey[0] == 0x04:
        if len(pubkey) != 65:
            #  Non-canonical public key: invalid length for uncompressed key
            return False
    elif pubkey[0] == 0x02 or pubkey[0] == 0x03:
        if len(pubkey) != 33:
            #  Non-canonical public key: invalid length for compressed key
            return False
    else:
        #  Non-canonical public key: neither compressed nor uncompressed
        return False

    return True


def _IsCompressedPubKey(pubkey: bytes) -> bool:
    if len(pubkey) != 33:
        #  Non-canonical public key: invalid length for compressed key
        return False

    if pubkey[0] != 0x02 and pubkey[0] != 0x03:
        #  Non-canonical public key: invalid prefix for compressed key
        return False

    return True


def _IsMinimalPush(opcode: int, data: bytes) -> bool:
    dlen = len(data)
    if dlen == 0:
        return opcode == OP_0
    if dlen == 1 and data[0] == 0x81:
        return opcode == OP_1NEGATE
    if dlen == 1 and 1 <= data[0] <= 16:
        return opcode == (OP_1 - 1 + data[0])
    if dlen <= 75:
        return opcode == dlen
    if dlen <= 255:
        return opcode == OP_PUSHDATA1
    if dlen <= 65535:
        return opcode == OP_PUSHDATA2
    return True


def _is_op_success(opcode: int) -> bool:
    """OP_SUCCESSx set defined in BIP342."""
    return opcode in (
        80, 98,
        126, 127, 128, 129,
        131, 132, 133, 134,
        137, 138,
        141, 142,
        149, 150, 151, 152, 153
    ) or 187 <= opcode <= 254


def _taproot_merkle_root(control: bytes, tapleaf_hash: bytes) -> bytes:
    assert len(control) >= TAPROOT_CONTROL_BASE_SIZE
    assert (len(control) - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0
    path_len = (len(control) - TAPROOT_CONTROL_BASE_SIZE) // TAPROOT_CONTROL_NODE_SIZE
    k = tapleaf_hash
    tbh = bitcointx.core.CoreCoinParams.tapbranch_hasher
    for i in range(path_len):
        node = control[TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i:
                       TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * (i + 1)]
        if node < k:
            k = tbh(node + k)
        else:
            k = tbh(k + node)
    return k


def _serialize_witness_stack_size(stack: Sequence[bytes]) -> int:
    """Return serialized size of the witness stack."""
    f = BytesIO()
    VarIntSerializer.stream_serialize(len(stack), f)
    for item in stack:
        BytesSerializer.stream_serialize(item, f)
    return len(f.getvalue())


# --- RAWBIT PATCH START: CLTV / CSV helpers ----------------------------
def _CheckLockTimeVerify(stack, txTo, inIdx, flags, get_eval_state):
    """BIP-65  –  OP_CHECKLOCKTIMEVERIFY"""
    if len(stack) < 1:
        raise MissingOpArgumentsError(get_eval_state(), expected_stack_depth=1)

    nLockTime = _CastToBigNum(stack[-1], get_eval_state, max_len=5)
    if nLockTime < 0:
        raise EvalScriptError("negative lock-time", get_eval_state())

    # locktime types must match (height vs. timestamp)
    if (nLockTime < LOCKTIME_THRESHOLD and txTo.nLockTime >= LOCKTIME_THRESHOLD) or \
       (nLockTime >= LOCKTIME_THRESHOLD and txTo.nLockTime < LOCKTIME_THRESHOLD):
        raise EvalScriptError("CLTV lock-time type mismatch", get_eval_state())

    if nLockTime > txTo.nLockTime:
        raise EvalScriptError("CLTV lock-time not satisfied", get_eval_state())

    # nSequence must not be final
    if txTo.vin[inIdx].nSequence == 0xFFFFFFFF:
        raise EvalScriptError("CLTV input is final", get_eval_state())


def _CheckSequenceVerify(stack, txTo, inIdx, flags, get_eval_state):
    """BIP-112 –  OP_CHECKSEQUENCEVERIFY"""
    if len(stack) < 1:
        raise MissingOpArgumentsError(get_eval_state(), expected_stack_depth=1)

    nSequence = _CastToBigNum(stack[-1], get_eval_state, max_len=5)
    if nSequence < 0:
        raise EvalScriptError("negative sequence", get_eval_state())

    # disabled flag means "anyone-can-spend" in CSV context
    if nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        return

    if txTo.nVersion < 2:
        raise EvalScriptError("CSV requires transaction version >= 2", get_eval_state())

    txSequence = txTo.vin[inIdx].nSequence
    if txSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        raise EvalScriptError("CSV not enabled in nSequence", get_eval_state())

    # type must match (height vs. time)
    same_type = (nSequence & SEQUENCE_LOCKTIME_TYPE_FLAG) == \
                (txSequence & SEQUENCE_LOCKTIME_TYPE_FLAG)
    if not same_type:
        raise EvalScriptError("CSV type mismatch", get_eval_state())

    # compare masked values
    if (nSequence & SEQUENCE_LOCKTIME_MASK) > (txSequence & SEQUENCE_LOCKTIME_MASK):
        raise EvalScriptError("CSV lock not yet satisfied", get_eval_state())
# --- RAWBIT PATCH END ---------------------------------------------------


def VerifyWitnessProgram(witness: CScriptWitness,
                         witversion: int, program: bytes,
                         txTo: 'bitcointx.core.CTransaction',
                         inIdx: int,
                         flags: Set[ScriptVerifyFlag_Type] = set(),
                         amount: int = 0,
                         script_class: Type[CScript] = CScript,
                         spent_outputs: Optional[Sequence['bitcointx.core.CTxOut']] = None,
                         execdata: Optional[ScriptExecutionData] = None,
                         # --- RAWBIT PATCH START: tracing hook -----------
                         on_step: Optional[Callable[[dict], None]] = None
                         # --- RAWBIT PATCH END ---------------------------
                         , *, is_p2sh_wrapped: bool = False) -> None:

    if script_class is None:
        raise ValueError("script class must be specified")

    if execdata is None:
        execdata = ScriptExecutionData()

    # --- Segwit v0 ------------------------------------------------------
    if witversion == 0:
        sigversion = SIGVERSION_WITNESS_V0
        stack = list(witness.stack)
        if len(program) == 32:
            if len(stack) == 0:
                raise VerifyScriptError("witness is empty")

            scriptPubKey = script_class(stack.pop())
            hashScriptPubKey = hashlib.sha256(scriptPubKey).digest()
            if hashScriptPubKey != program:
                raise VerifyScriptError("witness program mismatch")
        elif len(program) == 20:
            if len(stack) != 2:
                raise VerifyScriptError("witness program mismatch")  # 2 items in witness

            scriptPubKey = script_class([OP_DUP, OP_HASH160, program,
                                         OP_EQUALVERIFY, OP_CHECKSIG])
        else:
            raise VerifyScriptError("wrong length for witness program")

        for i, elt in enumerate(stack):
            elt_len = len(script_class([elt])) if isinstance(elt, int) else len(elt)
            if elt_len > MAX_SCRIPT_ELEMENT_SIZE:
                raise VerifyScriptError(
                    "maximum push size exceeded by an item at position {} "
                    "on witness stack".format(i))

        EvalScript(stack, scriptPubKey, txTo, inIdx,
                   flags=flags, amount=amount, sigversion=sigversion,
                   on_step=on_step, phase="witnessScript",
                   execdata=execdata, spent_outputs=spent_outputs)

        if len(stack) == 0:
            raise VerifyScriptError("scriptPubKey left an empty stack")
        elif len(stack) != 1:
            raise VerifyScriptError("scriptPubKey left extra items on stack")

        if not _CastToBool(stack[-1]):
            raise VerifyScriptError("scriptPubKey returned false")
        return

    # --- Taproot (BIP341/342) ------------------------------------------
    if witversion == 1 and len(program) == WITNESS_V1_TAPROOT_SIZE:
        if SCRIPT_VERIFY_TAPROOT not in flags:
            if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in flags:
                raise VerifyScriptError("upgradeable witness program is not accepted")
            return
        if is_p2sh_wrapped:
            if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in flags:
                raise VerifyScriptError("upgradeable witness program is not accepted")
            return
        stack = list(witness.stack)
        if len(stack) == 0:
            raise VerifyScriptError("witness is empty")

        # Optional annex
        if len(stack) >= 2 and len(stack[-1]) > 0 and stack[-1][0] == ANNEX_TAG:
            annex = stack.pop()
            annex_serialized = BytesSerializer.serialize(annex)
            # BIP341: annex hash over compact_size(annex) || annex
            execdata.annex_hash = hashlib.sha256(annex_serialized).digest()
            execdata.annex_present = True
        else:
            execdata.annex_hash = None
            execdata.annex_present = False
        execdata.annex_init = True

        # Key-path (only signature left)
        if len(stack) == 1:
            if spent_outputs is None:
                raise VerifyScriptError("spent_outputs are required for taproot key path verification")
            sig = stack[0]
            if len(sig) not in (64, 65):
                raise VerifyScriptError("invalid schnorr signature size")
            if len(sig) == 65 and (sig[-1] == 0 or sig[-1] not in VALID_SCHNORR_HASHTYPES):
                raise VerifyScriptError("invalid schnorr hashtype")

            hashtype = None if len(sig) == 64 else SIGHASH_Type(sig[-1])
            sh = SignatureHashSchnorr(
                txTo, inIdx, spent_outputs,
                hashtype=hashtype,
                sigversion=SIGVERSION_TAPROOT,
                annex_hash=execdata.annex_hash
            )
            xpk = bitcointx.core.key.XOnlyPubKey(program)
            if not xpk.verify_schnorr(sh, sig[:64]):
                raise VerifyScriptError("schnorr signature check failed")
            return

        # Script-path (control + script + stack)
        control = stack.pop()
        script_bytes = stack.pop()
        if (len(control) < TAPROOT_CONTROL_BASE_SIZE
                or len(control) > TAPROOT_CONTROL_MAX_SIZE
                or (len(control) - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0):
            raise VerifyScriptError("taproot control block has wrong size")

        leaf_version = control[0] & TAPROOT_LEAF_MASK
        tapleaf_hash = bitcointx.core.CoreCoinParams.tapleaf_hasher(
            bytes([leaf_version]) + BytesSerializer.serialize(script_bytes)
        )
        execdata.tapleaf_hash = tapleaf_hash
        execdata.tapleaf_hash_init = True
        execdata.codeseparator_pos = 0xFFFFFFFF
        execdata.codeseparator_pos_init = True

        merkle_root = _taproot_merkle_root(control, tapleaf_hash)
        internal_pub = bitcointx.core.key.XOnlyPubKey(control[1:33])
        tweaked = bitcointx.core.key.XOnlyPubKey(program)
        if not bitcointx.core.key.check_tap_tweak(
                tweaked, internal_pub, merkle_root=merkle_root, parity=bool(control[0] & 1)):
            raise VerifyScriptError("witness program mismatch")

        if leaf_version != TAPROOT_LEAF_TAPSCRIPT:
            if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION in flags:
                raise VerifyScriptError("taproot leaf version not supported")
            return

        if spent_outputs is None:
            raise VerifyScriptError("spent_outputs are required for tapscript verification")

        # OP_SUCCESSx pre-scan
        for (opcode, data, sop_idx) in script_class(script_bytes).raw_iter():
            if _is_op_success(int(opcode)):
                if SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS in flags:
                    raise VerifyScriptError("OP_SUCCESSx discouraged by policy")
                return

        for i, elt in enumerate(stack):
            elt_len = len(script_class([elt])) if isinstance(elt, int) else len(elt)
            if elt_len > MAX_SCRIPT_ELEMENT_SIZE:
                raise VerifyScriptError(
                    "maximum push size exceeded by an item at position {} "
                    "on witness stack".format(i))
        if len(stack) > MAX_STACK_ITEMS:
            raise VerifyScriptError("witness stack exceeds maximum items")

        execdata.validation_weight_left = _serialize_witness_stack_size(witness.stack) + VALIDATION_WEIGHT_OFFSET
        execdata.validation_weight_left_init = True

        exec_script = script_class(script_bytes)
        EvalScript(stack, exec_script, txTo, inIdx, flags=flags,
                   amount=amount, sigversion=SIGVERSION_TAPSCRIPT,
                   on_step=on_step, phase="witnessScript",
                   execdata=execdata, spent_outputs=spent_outputs)

        if len(stack) == 0:
            raise VerifyScriptError("scriptPubKey left an empty stack")
        elif len(stack) != 1:
            raise VerifyScriptError("scriptPubKey left extra items on stack")
        if not _CastToBool(stack[-1]):
            raise VerifyScriptError("scriptPubKey returned false")
        return

    if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in flags:
        raise VerifyScriptError("upgradeable witness program is not accepted")
    # Higher version witness scripts return true for future softfork compatibility
    return


def _CastToBigNum(b: bytes, get_eval_state: Callable[[], ScriptEvalState],
                  *, max_len: int = MAX_NUM_SIZE) -> int:
    state = get_eval_state()
    flags = state.flags or set()
    if len(b) > max_len:
        raise EvalScriptError('CastToBigNum() : overflow', state)

    if SCRIPT_VERIFY_MINIMALDATA in flags and len(b) > 0:
        # Reject non-minimal numeric encodings
        # - Zero must be encoded as empty
        # - No redundant sign/parity bytes
        if (b[-1] & 0x7f) == 0:
            if len(b) == 1:
                raise VerifyScriptError("non-minimally encoded number")
            if (b[-2] & 0x80) == 0:
                raise VerifyScriptError("non-minimally encoded number")

    v = bitcointx.core._bignum.vch2bn(b)
    if v is None:
        raise EvalScriptError('CastToBigNum() : invalid value', state)
    return v


def _CastToBool(b: bytes) -> bool:
    for i in range(len(b)):
        bv = b[i]
        if bv != 0:
            if (i == (len(b) - 1)) and (bv == 0x80):
                return False
            return True

    return False


def _CheckSig(sig: bytes, pubkey: bytes, script: CScript,
              txTo: 'bitcointx.core.CTransaction', inIdx: int,
              flags: Set[ScriptVerifyFlag_Type], amount: int = 0,
              sigversion: SIGVERSION_Type = SIGVERSION_BASE) -> bool:
    key = bitcointx.core.key.CPubKey(pubkey)

    if len(sig) == 0:
        return False

    hashtype = sig[-1]

    if flags & _STRICT_ENCODING_FLAGS:
        verify_fn = key.verify

        if not _IsValidSignatureEncoding(sig):
            raise VerifyScriptError(
                "signature DER encoding is not strictly valid")

        if SCRIPT_VERIFY_STRICTENC in flags:
            low_hashtype = hashtype & (~SIGHASH_ANYONECANPAY)
            if low_hashtype < SIGHASH_ALL or low_hashtype > SIGHASH_SINGLE:
                raise VerifyScriptError("unknown hashtype in signature")

            if not _IsCompressedOrUncompressedPubKey(pubkey):
                raise VerifyScriptError("unknown pubkey type")
    else:
        verify_fn = key.verify_nonstrict

    if SCRIPT_VERIFY_WITNESS_PUBKEYTYPE in flags and sigversion == SIGVERSION_WITNESS_V0:
        if not _IsCompressedPubKey(pubkey):
            raise VerifyScriptError("witness pubkey is not compressed")

    if SCRIPT_VERIFY_LOW_S in flags and not IsLowDERSignature(sig):
        raise VerifyScriptError("signature is not low-S")

    # Raw signature hash due to the SIGHASH_SINGLE bug
    (h, err) = script.raw_sighash(
        txTo, inIdx, hashtype, amount=amount, sigversion=sigversion)

    return verify_fn(h, sig[:-1])


def _CheckMultiSig(opcode: CScriptOp, script: CScript,
                   stack: List[bytes], txTo: 'bitcointx.core.CTransaction',
                   inIdx: int, flags: Set[ScriptVerifyFlag_Type],
                   get_eval_state: Callable[[], ScriptEvalState],
                   nOpCount: List[int], amount: int = 0,
                   sigversion: SIGVERSION_Type = SIGVERSION_BASE) -> None:

    i = 1
    if len(stack) < i:
        raise MissingOpArgumentsError(get_eval_state(), expected_stack_depth=i)

    keys_count = _CastToBigNum(stack[-i], get_eval_state)
    if keys_count < 0 or keys_count > 20:
        raise ArgumentsInvalidError("keys count invalid", get_eval_state())
    i += 1
    ikey = i
    # ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
    # With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
    ikey2 = keys_count + 2
    i += keys_count
    nOpCount[0] += keys_count
    if nOpCount[0] > MAX_SCRIPT_OPCODES:
        raise MaxOpCountError(get_eval_state())
    if len(stack) < i:
        raise ArgumentsInvalidError("not enough keys on stack",
                                    get_eval_state())

    sigs_count = _CastToBigNum(stack[-i], get_eval_state)
    if sigs_count < 0 or sigs_count > keys_count:
        raise ArgumentsInvalidError("sigs count invalid", get_eval_state())

    i += 1
    isig = i
    i += sigs_count
    if len(stack) < i-1:
        raise ArgumentsInvalidError("not enough sigs on stack",
                                    get_eval_state())
    elif len(stack) < i:
        raise ArgumentsInvalidError("missing dummy value", get_eval_state())

    if sigversion == SIGVERSION_BASE:
        # Drop the signature in pre-segwit scripts but not segwit scripts
        for k in range(sigs_count):
            sig = stack[-isig - k]
            script = FindAndDelete(script, script.__class__([sig]))

    success = True

    empty_sig_count = 0
    while success and sigs_count > 0:
        sig = stack[-isig]
        empty_sig_count += int(len(sig) == 0)
        pubkey = stack[-ikey]

        if _CheckSig(sig, pubkey, script, txTo, inIdx, flags,
                     amount=amount, sigversion=sigversion):
            isig += 1
            sigs_count -= 1

        ikey += 1
        keys_count -= 1

        if sigs_count > keys_count:
            success = False

            # with VERIFY bail now before we modify the stack
            if opcode == OP_CHECKMULTISIGVERIFY:
                raise VerifyOpFailedError(get_eval_state())

    while i > 1:
        if not success and SCRIPT_VERIFY_NULLFAIL in flags and ikey2 == 0 and len(stack[-1]):
            raise VerifyScriptError("signature check failed, and some of the signatures are not empty")

        if ikey2 > 0:
            ikey2 -= 1

        stack.pop()
        i -= 1

    # Note how Bitcoin Core duplicates the len(stack) check, rather than
    # letting pop() handle it; maybe that's wrong?
    if len(stack) and SCRIPT_VERIFY_NULLDUMMY in flags:
        if stack[-1] != b'':
            raise ArgumentsInvalidError("dummy value not OP_0",
                                        get_eval_state())

    stack.pop()

    if opcode == OP_CHECKMULTISIG:
        if success:
            stack.append(b"\x01")
        else:
            stack.append(b"")


# OP_2MUL and OP_2DIV are *not* included in this list as they are disabled
_ISA_UNOP = {
    OP_1ADD,
    OP_1SUB,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
}


def _UnaryOp(opcode: CScriptOp, stack: List[bytes],
             get_eval_state: Callable[[], ScriptEvalState]) -> None:
    if len(stack) < 1:
        raise MissingOpArgumentsError(get_eval_state(), expected_stack_depth=1)
    bn = _CastToBigNum(stack[-1], get_eval_state)
    stack.pop()

    if opcode == OP_1ADD:
        bn += 1

    elif opcode == OP_1SUB:
        bn -= 1

    elif opcode == OP_NEGATE:
        bn = -bn

    elif opcode == OP_ABS:
        if bn < 0:
            bn = -bn

    elif opcode == OP_NOT:
        bn = int(bn == 0)

    elif opcode == OP_0NOTEQUAL:
        bn = int(bn != 0)

    else:
        raise AssertionError("Unknown unary opcode encountered; this should not happen")

    stack.append(bitcointx.core._bignum.bn2vch(bn))


# OP_LSHIFT and OP_RSHIFT are *not* included in this list as they are disabled
_ISA_BINOP = {
    OP_ADD,
    OP_SUB,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,
}


def _BinOp(opcode: CScriptOp, stack: List[bytes],
           get_eval_state: Callable[[], ScriptEvalState]) -> None:
    if len(stack) < 2:
        raise MissingOpArgumentsError(get_eval_state(), expected_stack_depth=2)

    bn2 = _CastToBigNum(stack[-1], get_eval_state)
    bn1 = _CastToBigNum(stack[-2], get_eval_state)

    # We don't pop the stack yet so that OP_NUMEQUALVERIFY can raise
    # VerifyOpFailedError with a correct stack.

    if opcode == OP_ADD:
        bn = bn1 + bn2

    elif opcode == OP_SUB:
        bn = bn1 - bn2

    elif opcode == OP_BOOLAND:
        bn = int(bn1 != 0 and bn2 != 0)

    elif opcode == OP_BOOLOR:
        bn = int(bn1 != 0 or bn2 != 0)

    elif opcode == OP_NUMEQUAL:
        bn = int(bn1 == bn2)

    elif opcode == OP_NUMEQUALVERIFY:
        bn = int(bn1 == bn2)
        if not bn:
            raise VerifyOpFailedError(get_eval_state())
        else:
            # No exception, so time to pop the stack
            stack.pop()
            stack.pop()
            return

    elif opcode == OP_NUMNOTEQUAL:
        bn = int(bn1 != bn2)

    elif opcode == OP_LESSTHAN:
        bn = int(bn1 < bn2)

    elif opcode == OP_GREATERTHAN:
        bn = int(bn1 > bn2)

    elif opcode == OP_LESSTHANOREQUAL:
        bn = int(bn1 <= bn2)

    elif opcode == OP_GREATERTHANOREQUAL:
        bn = int(bn1 >= bn2)

    elif opcode == OP_MIN:
        if bn1 < bn2:
            bn = bn1
        else:
            bn = bn2

    elif opcode == OP_MAX:
        if bn1 > bn2:
            bn = bn1
        else:
            bn = bn2

    else:
        raise AssertionError("Unknown binop opcode encountered; this should not happen")

    stack.pop()
    stack.pop()
    stack.append(bitcointx.core._bignum.bn2vch(bn))


def _CheckExec(vfExec: List[bool]) -> bool:
    for b in vfExec:
        if not b:
            return False
    return True


# --- RAWBIT PATCH START: TraceStep type --------------------------------
class TraceStep(TypedDict, total=False):
    pc: int
    opcode: int
    opcode_name: str
    stack_before: List[str]
    stack_after: List[str]
    phase: str
    failed: bool
    error: str
# --- RAWBIT PATCH END ---------------------------------------------------


def _EvalScript(stack: List[bytes], scriptIn: CScript,
                txTo: 'bitcointx.core.CTransaction',
                inIdx: int, flags: Set[ScriptVerifyFlag_Type] = set(),
                amount: int = 0, sigversion: SIGVERSION_Type = SIGVERSION_BASE,
                # --- RAWBIT PATCH START: tracing hook + phase ----------
                on_step: Optional[Callable[[TraceStep], None]] = None,
                phase: str = "script",
                execdata: Optional[ScriptExecutionData] = None,
                spent_outputs: Optional[Sequence['bitcointx.core.CTxOut']] = None
                # --- RAWBIT PATCH END ----------------------------------
                ) -> None:
    """Evaluate a script

    """
    if sigversion != SIGVERSION_TAPSCRIPT and len(scriptIn) > MAX_SCRIPT_SIZE:
        raise EvalScriptError((f'script too large; got {len(scriptIn)} bytes; '
                               f'maximum {MAX_SCRIPT_SIZE} bytes'),
                              ScriptEvalState(stack=stack, scriptIn=scriptIn,
                                              txTo=txTo, inIdx=inIdx,
                                              flags=flags))

    altstack: List[bytes] = []
    vfExec: List[bool] = []
    pbegincodehash = 0
    nOpCount = [0]
    v_bytes: bytes
    v_int: int
    if execdata is None:
        execdata = ScriptExecutionData()
    v_bool: bool
    opcode_pos = 0
    for (sop, sop_data, sop_pc) in scriptIn.raw_iter():
        fExec = _CheckExec(vfExec)

        def get_eval_state() -> ScriptEvalState:
            return ScriptEvalState(
                sop=sop,
                sop_data=sop_data,
                sop_pc=sop_pc,
                stack=stack,
                scriptIn=scriptIn,
                txTo=txTo,
                inIdx=inIdx,
                flags=flags,
                altstack=altstack,
                vfExec=vfExec,
                pbegincodehash=pbegincodehash,
                nOpCount=nOpCount[0])

        # --- RAWBIT PATCH: capture stack_before only if tracing
        stack_before: Optional[List[str]] = None
        if on_step is not None:
            stack_before = [x.hex() for x in stack]

        try:
            if sigversion == SIGVERSION_TAPSCRIPT and _is_op_success(int(sop)):
                if SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS in flags:
                    raise EvalScriptError('OP_SUCCESSx encountered', get_eval_state())
                # Short-circuit success for OP_SUCCESSx
                stack[:] = [b"\x01"]
                return
            if sop in DISABLED_OPCODES:
                raise EvalScriptError(f'opcode {_opcode_name(sop)} is disabled',
                                      get_eval_state())

            if sop > OP_16 and sigversion != SIGVERSION_TAPSCRIPT:
                nOpCount[0] += 1
                if nOpCount[0] > MAX_SCRIPT_OPCODES:
                    raise MaxOpCountError(get_eval_state())

            def check_args(n: int) -> None:
                if len(stack) < n:
                    raise MissingOpArgumentsError(get_eval_state(),
                                                  expected_stack_depth=n)

            if sop <= OP_PUSHDATA4:
                assert sop_data is not None
                if len(sop_data) > MAX_SCRIPT_ELEMENT_SIZE:
                    raise EvalScriptError(
                        (f'PUSHDATA of length {len(sop_data)}; '
                         f'maximum allowed is {MAX_SCRIPT_ELEMENT_SIZE}'),
                        get_eval_state())

                elif fExec:
                    if SCRIPT_VERIFY_MINIMALDATA in flags:
                        if not _IsMinimalPush(int(sop), sop_data):
                            raise VerifyScriptError("non-minimal data push")
                    stack.append(sop_data)
                    if len(stack) + len(altstack) > MAX_STACK_ITEMS:
                        raise EvalScriptError('max stack items limit reached',
                                              get_eval_state())
                    # --- RAWBIT: record step before continue (to preserve original flow)
                    if on_step is not None:
                        on_step({
                            "pc": sop_pc,
                            "opcode": int(sop),
                            "opcode_name": _opcode_name(sop),
                            "stack_before": stack_before or [],
                            "stack_after": [x.hex() for x in stack],
                            "phase": phase,
                        })
                    opcode_pos += 1
                    continue

            elif fExec or (OP_IF <= sop <= OP_ENDIF):

                if sop == OP_1NEGATE or ((sop >= OP_1) and (sop <= OP_16)):
                    v_int = sop - (OP_1 - 1)
                    stack.append(bitcointx.core._bignum.bn2vch(v_int))

                elif sop in _ISA_BINOP:
                    _BinOp(sop, stack, get_eval_state)

                elif sop in _ISA_UNOP:
                    _UnaryOp(sop, stack, get_eval_state)

                elif sop == OP_2DROP:
                    check_args(2)
                    stack.pop()
                    stack.pop()

                elif sop == OP_2DUP:
                    check_args(2)
                    v1 = stack[-2]
                    v2 = stack[-1]
                    stack.append(v1)
                    stack.append(v2)

                elif sop == OP_2OVER:
                    check_args(4)
                    v1 = stack[-4]
                    v2 = stack[-3]
                    stack.append(v1)
                    stack.append(v2)

                elif sop == OP_2ROT:
                    check_args(6)
                    v1 = stack[-6]
                    v2 = stack[-5]
                    del stack[-6]
                    del stack[-5]
                    stack.append(v1)
                    stack.append(v2)

                elif sop == OP_2SWAP:
                    check_args(4)
                    tmp = stack[-4]
                    stack[-4] = stack[-2]
                    stack[-2] = tmp

                    tmp = stack[-3]
                    stack[-3] = stack[-1]
                    stack[-1] = tmp

                elif sop == OP_3DUP:
                    check_args(3)
                    v1 = stack[-3]
                    v2 = stack[-2]
                    v3 = stack[-1]
                    stack.append(v1)
                    stack.append(v2)
                    stack.append(v3)

                elif sop == OP_CHECKMULTISIG or sop == OP_CHECKMULTISIGVERIFY:
                    if sigversion == SIGVERSION_TAPSCRIPT:
                        raise EvalScriptError("OP_CHECKMULTISIG invalid in tapscript",
                                              get_eval_state())
                    tmpScript = scriptIn.__class__(scriptIn[pbegincodehash:])
                    _CheckMultiSig(sop, tmpScript, stack, txTo, inIdx, flags,
                                   get_eval_state, nOpCount,
                                   amount=amount, sigversion=sigversion)

                elif sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
                    check_args(2)
                    vchPubKey = stack[-1]
                    vchSig = stack[-2]

                    if sigversion == SIGVERSION_TAPSCRIPT:
                        if execdata is None or not execdata.validation_weight_left_init:
                            raise EvalScriptError("missing tapscript execdata", get_eval_state())
                        success = len(vchSig) != 0
                        if success:
                            execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED
                            if execdata.validation_weight_left < 0:
                                raise VerifyScriptError("tapscript validation weight exceeded")
                        if len(vchPubKey) == 0:
                            raise VerifyScriptError("pubkey is empty")
                        elif len(vchPubKey) == 32:
                            if success:
                                if spent_outputs is None or not execdata.tapleaf_hash_init or not execdata.codeseparator_pos_init:
                                    raise EvalScriptError("missing taproot context for sighash", get_eval_state())
                                if len(vchSig) not in (64, 65):
                                    raise VerifyScriptError("invalid schnorr signature size")
                                if len(vchSig) == 65 and (vchSig[-1] == 0 or vchSig[-1] not in VALID_SCHNORR_HASHTYPES):
                                    raise VerifyScriptError("invalid schnorr hashtype")
                                hashtype = None if len(vchSig) == 64 else SIGHASH_Type(vchSig[-1])
                                sh = SignatureHashSchnorr(
                                    txTo, inIdx, spent_outputs,
                                    hashtype=hashtype,
                                    sigversion=SIGVERSION_TAPSCRIPT,
                                    tapleaf_hash=execdata.tapleaf_hash,
                                    codeseparator_pos=execdata.codeseparator_pos,
                                    annex_hash=execdata.annex_hash
                                )
                                xpk = bitcointx.core.key.XOnlyPubKey(vchPubKey)
                                if not xpk.verify_schnorr(sh, vchSig[:64]):
                                    raise VerifyScriptError("schnorr signature verification failed")
                        else:
                            if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE in flags:
                                raise VerifyScriptError("upgradable pubkey type discouraged")

                        stack.pop()
                        stack.pop()
                        if sop == OP_CHECKSIGVERIFY:
                            if not success:
                                raise VerifyOpFailedError(get_eval_state())
                        else:
                            stack.append(b"\x01" if success else b"")
                    else:
                        # legacy / segwit v0 path
                        tmpScript = scriptIn.__class__(scriptIn[pbegincodehash:])

                        if sigversion == SIGVERSION_BASE:
                            tmpScript = FindAndDelete(tmpScript,
                                                      scriptIn.__class__([vchSig]))

                        ok = _CheckSig(vchSig, vchPubKey, tmpScript, txTo, inIdx, flags,
                                       amount=amount, sigversion=sigversion)
                        if not ok and SCRIPT_VERIFY_NULLFAIL in flags and len(vchSig):
                            raise VerifyScriptError("signature check failed, and signature is not empty")
                        if not ok and sop == OP_CHECKSIGVERIFY:
                            raise VerifyOpFailedError(get_eval_state())
                        else:
                            stack.pop()
                            stack.pop()
                            if ok:
                                if sop != OP_CHECKSIGVERIFY:
                                    stack.append(b"\x01")
                            else:
                                stack.append(b"")

                elif sop == OP_CHECKSIGADD:
                    if sigversion != SIGVERSION_TAPSCRIPT:
                        raise EvalScriptError("OP_CHECKSIGADD invalid before tapscript",
                                              get_eval_state())
                    check_args(3)
                    sig = stack[-3]
                    num = _CastToBigNum(stack[-2], get_eval_state)
                    pubkey = stack[-1]
                    success = len(sig) != 0
                    if len(pubkey) == 0:
                        raise VerifyScriptError("pubkey is empty")
                    if len(pubkey) != 32 and SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE in flags:
                        raise VerifyScriptError("upgradable pubkey type discouraged")
                    if success:
                        if execdata is None or not execdata.validation_weight_left_init:
                            raise EvalScriptError("missing tapscript execdata", get_eval_state())
                        execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED
                        if execdata.validation_weight_left < 0:
                            raise VerifyScriptError("tapscript validation weight exceeded")
                        if len(pubkey) == 32:
                            if len(sig) not in (64, 65):
                                raise VerifyScriptError("invalid schnorr signature size")
                            if len(sig) == 65 and (sig[-1] == 0 or sig[-1] not in VALID_SCHNORR_HASHTYPES):
                                raise VerifyScriptError("invalid schnorr hashtype")
                            if spent_outputs is None or execdata is None or not execdata.tapleaf_hash_init or not execdata.codeseparator_pos_init:
                                raise EvalScriptError("missing taproot context for sighash", get_eval_state())
                            hashtype = None if len(sig) == 64 else SIGHASH_Type(sig[-1])
                            sh = SignatureHashSchnorr(
                                txTo, inIdx, spent_outputs,
                                hashtype=hashtype,
                                sigversion=SIGVERSION_TAPSCRIPT,
                                tapleaf_hash=execdata.tapleaf_hash,
                                codeseparator_pos=execdata.codeseparator_pos,
                                annex_hash=execdata.annex_hash
                            )
                            xpk = bitcointx.core.key.XOnlyPubKey(pubkey)
                            if not xpk.verify_schnorr(sh, sig[:64]):
                                raise VerifyScriptError("schnorr signature verification failed")

                    # consume arguments
                    stack.pop()
                    stack.pop()
                    stack.pop()
                    stack.append(bitcointx.core._bignum.bn2vch(num + (1 if success else 0)))

                elif sop == OP_CODESEPARATOR:
                    pbegincodehash = sop_pc
                    if sigversion == SIGVERSION_TAPSCRIPT:
                        execdata.codeseparator_pos = opcode_pos
                        execdata.codeseparator_pos_init = True

                elif sop == OP_DEPTH:
                    bn = len(stack)
                    stack.append(bitcointx.core._bignum.bn2vch(bn))

                elif sop == OP_DROP:
                    check_args(1)
                    stack.pop()

                elif sop == OP_DUP:
                    check_args(1)
                    v_bytes = stack[-1]
                    stack.append(v_bytes)

                elif sop == OP_ELSE:
                    if len(vfExec) == 0:
                        raise EvalScriptError('ELSE found without prior IF',
                                              get_eval_state())
                    vfExec[-1] = not vfExec[-1]

                elif sop == OP_ENDIF:
                    if len(vfExec) == 0:
                        raise EvalScriptError('ENDIF found without prior IF',
                                              get_eval_state())
                    vfExec.pop()

                elif sop == OP_EQUAL:
                    check_args(2)
                    v1 = stack.pop()
                    v2 = stack.pop()

                    if v1 == v2:
                        stack.append(b"\x01")
                    else:
                        stack.append(b"")

                elif sop == OP_EQUALVERIFY:
                    check_args(2)
                    v1 = stack[-1]
                    v2 = stack[-2]

                    if v1 == v2:
                        stack.pop()
                        stack.pop()
                    else:
                        raise VerifyOpFailedError(get_eval_state())

                elif sop == OP_FROMALTSTACK:
                    if len(altstack) < 1:
                        raise MissingOpArgumentsError(get_eval_state(),
                                                      expected_stack_depth=1)
                    v_bytes = altstack.pop()
                    stack.append(v_bytes)

                elif sop == OP_HASH160:
                    check_args(1)
                    stack.append(bitcointx.core.serialize.Hash160(stack.pop()))

                elif sop == OP_HASH256:
                    check_args(1)
                    stack.append(bitcointx.core.serialize.Hash(stack.pop()))

                elif sop == OP_IF or sop == OP_NOTIF:
                    val = False

                    if fExec:
                        check_args(1)
                        vch = stack.pop()

                        if sigversion == SIGVERSION_TAPSCRIPT:
                            if len(vch) > 1 or (len(vch) == 1 and vch[0] != 1):
                                raise VerifyScriptError("SCRIPT_VERIFY_MINIMALIF check failed")
                        elif sigversion == SIGVERSION_WITNESS_V0 and SCRIPT_VERIFY_MINIMALIF in flags:
                            if len(vch) > 1:
                                raise VerifyScriptError("SCRIPT_VERIFY_MINIMALIF check failed")
                            if len(vch) == 1 and vch[0] != 1:
                                raise VerifyScriptError("SCRIPT_VERIFY_MINIMALIF check failed")

                        val = _CastToBool(vch)
                        if sop == OP_NOTIF:
                            val = not val

                    vfExec.append(val)

                elif sop == OP_IFDUP:
                    check_args(1)
                    vch = stack[-1]
                    if _CastToBool(vch):
                        stack.append(vch)

                elif sop == OP_NIP:
                    check_args(2)
                    del stack[-2]

                elif sop == OP_NOP:
                    pass

                # --- RAWBIT PATCH: CLTV / CSV support (BIP-65 / BIP-112)
                elif sop == OP_CHECKLOCKTIMEVERIFY:
                    if SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY in flags:
                        _CheckLockTimeVerify(stack, txTo, inIdx, flags, get_eval_state)
                    elif SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS in flags:
                        raise EvalScriptError(
                            f"{_opcode_name(sop)} reserved for soft-fork upgrades",
                            get_eval_state()
                        )
                    # else: treat as NOP

                elif sop == OP_CHECKSEQUENCEVERIFY:
                    if SCRIPT_VERIFY_CHECKSEQUENCEVERIFY in flags:
                        _CheckSequenceVerify(stack, txTo, inIdx, flags, get_eval_state)
                    elif SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS in flags:
                        raise EvalScriptError(
                            f"{_opcode_name(sop)} reserved for soft-fork upgrades",
                            get_eval_state()
                        )
                    # else: treat as NOP

                elif sop >= OP_NOP1 and sop <= OP_NOP10:
                    if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS in flags:
                        raise EvalScriptError((f"{_opcode_name(sop)} reserved "
                                               f"for soft-fork upgrades"),
                                              get_eval_state())
                    else:
                        pass

                elif sop == OP_OVER:
                    check_args(2)
                    vch = stack[-2]
                    stack.append(vch)

                elif sop == OP_PICK or sop == OP_ROLL:
                    check_args(2)
                    n = _CastToBigNum(stack.pop(), get_eval_state)
                    if n < 0 or n >= len(stack):
                        raise EvalScriptError(
                            f"Argument for {_opcode_name(sop)} out of bounds",
                            get_eval_state())
                    vch = stack[-n-1]
                    if sop == OP_ROLL:
                        del stack[-n-1]
                    stack.append(vch)

                elif sop == OP_RETURN:
                    raise EvalScriptError("OP_RETURN called", get_eval_state())

                elif sop == OP_RIPEMD160:
                    check_args(1)
                    stack.append(bitcointx.core._ripemd160.ripemd160(stack.pop()))

                elif sop == OP_ROT:
                    check_args(3)
                    tmp = stack[-3]
                    stack[-3] = stack[-2]
                    stack[-2] = tmp

                    tmp = stack[-2]
                    stack[-2] = stack[-1]
                    stack[-1] = tmp

                elif sop == OP_SIZE:
                    check_args(1)
                    bn = len(stack[-1])
                    stack.append(bitcointx.core._bignum.bn2vch(bn))

                elif sop == OP_SHA1:
                    check_args(1)
                    stack.append(hashlib.sha1(stack.pop()).digest())

                elif sop == OP_SHA256:
                    check_args(1)
                    stack.append(hashlib.sha256(stack.pop()).digest())

                elif sop == OP_SWAP:
                    check_args(2)
                    tmp = stack[-2]
                    stack[-2] = stack[-1]
                    stack[-1] = tmp

                elif sop == OP_TOALTSTACK:
                    check_args(1)
                    v_bytes = stack.pop()
                    altstack.append(v_bytes)

                elif sop == OP_TUCK:
                    check_args(2)
                    vch = stack[-1]
                    stack.insert(len(stack) - 2, vch)

                elif sop == OP_VERIFY:
                    check_args(1)
                    v_bool = _CastToBool(stack[-1])
                    if v_bool:
                        stack.pop()
                    else:
                        raise VerifyOpFailedError(get_eval_state())

                elif sop == OP_WITHIN:
                    check_args(3)
                    bn3 = _CastToBigNum(stack[-1], get_eval_state)
                    bn2 = _CastToBigNum(stack[-2], get_eval_state)
                    bn1 = _CastToBigNum(stack[-3], get_eval_state)
                    stack.pop()
                    stack.pop()
                    stack.pop()
                    v_bool = (bn2 <= bn1) and (bn1 < bn3)
                    if v_bool:
                        stack.append(b"\x01")
                    else:
                        stack.append(b"")

                else:
                    raise EvalScriptError('unsupported opcode 0x%x' % sop,
                                          get_eval_state())

            # size limits
            if len(stack) + len(altstack) > MAX_STACK_ITEMS:
                raise EvalScriptError('max stack items limit reached',
                                      get_eval_state())

            # --- RAWBIT PATCH: record successful step
            if on_step is not None:
                on_step({
                    "pc": sop_pc,
                    "opcode": int(sop),
                    "opcode_name": _opcode_name(sop),
                    "stack_before": stack_before or [],
                    "stack_after": [x.hex() for x in stack],
                    "phase": phase,
                })

        except Exception as e:
            # --- RAWBIT PATCH: record failing step before re-raising
            if on_step is not None:
                on_step({
                    "pc": sop_pc,
                    "opcode": int(sop),
                    "opcode_name": _opcode_name(sop),
                    "stack_before": stack_before or [],
                    "stack_after": [x.hex() for x in stack],
                    "phase": phase,
                    "failed": True,
                    "error": str(e),
                })
            raise

        opcode_pos += 1

    # Unterminated IF/NOTIF/ELSE block
    if len(vfExec):
        raise EvalScriptError(
            'Unterminated IF/ELSE block',
            ScriptEvalState(stack=stack, scriptIn=scriptIn,
                            txTo=txTo, inIdx=inIdx, flags=flags))


def EvalScript(stack: List[bytes], scriptIn: CScript,
               txTo: 'bitcointx.core.CTransaction',
               inIdx: int, flags: Set[ScriptVerifyFlag_Type] = set(),
               amount: int = 0, sigversion: SIGVERSION_Type = SIGVERSION_BASE,
               # --- RAWBIT PATCH START: optional tracing hook ----------
               on_step: Optional[Callable[[TraceStep], None]] = None,
               phase: str = "script",
               execdata: Optional[ScriptExecutionData] = None,
               spent_outputs: Optional[Sequence['bitcointx.core.CTxOut']] = None
               # --- RAWBIT PATCH END ----------------------------------
               ) -> None:
    """Evaluate a script

    stack      - Initial stack

    scriptIn   - Script

    txTo       - Transaction the script is a part of

    inIdx      - txin index of the scriptSig

    flags      - SCRIPT_VERIFY_* flags to apply

    sigversion - SIGVERSION_* version (not used for now)
    """

    try:
        _EvalScript(stack, scriptIn, txTo, inIdx, flags=flags, amount=amount,
                    sigversion=sigversion, on_step=on_step, phase=phase,
                    execdata=execdata, spent_outputs=spent_outputs)
    except CScriptInvalidError as err:
        raise EvalScriptError(
            repr(err), ScriptEvalState(stack=stack, scriptIn=scriptIn,
                                       txTo=txTo, inIdx=inIdx, flags=flags))


class VerifyScriptError(bitcointx.core.ValidationError):
    pass


def VerifyScript(scriptSig: CScript, scriptPubKey: CScript,
                 txTo: 'bitcointx.core.CTransaction', inIdx: int,
                 flags: Optional[Union[Tuple[ScriptVerifyFlag_Type, ...],
                                       Set[ScriptVerifyFlag_Type]]] = None,
                 amount: int = 0, witness: Optional[CScriptWitness] = None,
                 spent_outputs: Optional[Sequence['bitcointx.core.CTxOut']] = None
                 ) -> None:
    """Verify a scriptSig satisfies a scriptPubKey

    scriptSig    - Signature

    scriptPubKey - PubKey

    txTo         - Spending transaction

    inIdx        - Index of the transaction input containing scriptSig

    Raises a ValidationError subclass if the validation fails.
    """

    ensure_isinstance(scriptSig, CScript, 'scriptSig')
    if not type(scriptSig) == type(scriptPubKey):  # noqa: exact class check
        raise TypeError(
            "scriptSig and scriptPubKey must be of the same script class")

    script_class = scriptSig.__class__

    if flags is None:
        flags = STANDARD_SCRIPT_VERIFY_FLAGS - UNHANDLED_SCRIPT_VERIFY_FLAGS
    else:
        flags = set(flags)  # might be passed as tuple

    if SCRIPT_VERIFY_SIGPUSHONLY in flags and not scriptSig.is_push_only():
        raise VerifyScriptError("scriptSig is not push-only")

    if flags & UNHANDLED_SCRIPT_VERIFY_FLAGS:
        raise VerifyScriptError(
            "some of the flags cannot be handled by current code: {}"
            .format(script_verify_flags_to_string(flags & UNHANDLED_SCRIPT_VERIFY_FLAGS)))

    execdata = ScriptExecutionData()

    stack: List[bytes] = []
    EvalScript(stack, scriptSig, txTo, inIdx, flags=flags, phase="scriptSig",
               execdata=execdata, spent_outputs=spent_outputs)
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags, phase="scriptPubKey",
               execdata=execdata, spent_outputs=spent_outputs)
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    hadWitness = False
    if witness is None:
        witness = CScriptWitness([])

    if SCRIPT_VERIFY_WITNESS in flags and scriptPubKey.is_witness_scriptpubkey():
        hadWitness = True

        if scriptSig:
            raise VerifyScriptError("scriptSig is not empty")

        VerifyWitnessProgram(witness,
                             scriptPubKey.witness_version(),
                             scriptPubKey.witness_program(),
                             txTo, inIdx, flags=flags, amount=amount,
                             script_class=script_class,
                             spent_outputs=spent_outputs,
                             execdata=execdata,
                             is_p2sh_wrapped=False)

        # Bypass the cleanstack check at the end. The actual stack is obviously not clean
        # for witness programs.
        stack = stack[:1]

    # Additional validation for spend-to-script-hash transactions
    if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
        if not scriptSig.is_push_only():
            raise VerifyScriptError("P2SH scriptSig not is_push_only()")

        # restore stack
        stack = stackCopy

        # stack cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the EvalScript above would return false.
        assert len(stack)

        pubKey2 = script_class(stack.pop())

        EvalScript(stack, pubKey2, txTo, inIdx, flags=flags, phase="redeemScript",
                   execdata=execdata, spent_outputs=spent_outputs)

        if not len(stack):
            raise VerifyScriptError("P2SH inner scriptPubKey left an empty stack")

        if not _CastToBool(stack[-1]):
            raise VerifyScriptError("P2SH inner scriptPubKey returned false")

        # P2SH witness program
        if SCRIPT_VERIFY_WITNESS in flags and pubKey2.is_witness_scriptpubkey():
            hadWitness = True

            if scriptSig != script_class([pubKey2]):
                raise VerifyScriptError("scriptSig is not exactly a single push of the redeemScript")

            VerifyWitnessProgram(witness,
                                 pubKey2.witness_version(),
                                 pubKey2.witness_program(),
                                 txTo, inIdx, flags=flags, amount=amount,
                                 script_class=script_class,
                                 spent_outputs=spent_outputs,
                                 execdata=execdata,
                                 is_p2sh_wrapped=True)

            # Bypass the cleanstack check at the end. The actual stack is obviously not clean
            # for witness programs.
            stack = stack[:1]

    if SCRIPT_VERIFY_CLEANSTACK in flags:
        if SCRIPT_VERIFY_P2SH not in flags:
            raise ValueError(
                'SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_P2SH')

        if len(stack) == 0:
            raise VerifyScriptError("scriptPubKey left an empty stack")
        elif len(stack) != 1:
            raise VerifyScriptError("scriptPubKey left extra items on stack")

    if SCRIPT_VERIFY_WITNESS in flags:
        # We can't check for correct unexpected witness data if P2SH was off, so require
        # that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        # possible, which is not a softfork.
        if SCRIPT_VERIFY_P2SH not in flags:
            raise ValueError(
                "SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH")

        if not hadWitness and witness:
            raise VerifyScriptError("Unexpected witness")


class VerifySignatureError(bitcointx.core.ValidationError):
    pass


# XXX not tested for segwit, not covered by tests
def VerifySignature(txFrom: 'bitcointx.core.CTransaction',
                    txTo: 'bitcointx.core.CTransaction',
                    inIdx: int) -> None:
    """Verify a scriptSig signature can spend a txout

    Verifies that the scriptSig in txTo.vin[inIdx] is a valid scriptSig for the
    corresponding COutPoint in transaction txFrom.
    """
    if inIdx < 0:
        raise VerifySignatureError("inIdx negative")
    if inIdx >= len(txTo.vin):
        raise VerifySignatureError("inIdx >= len(txTo.vin)")
    txin = txTo.vin[inIdx]

    if txin.prevout.n < 0:
        raise VerifySignatureError("txin prevout.n negative")
    if txin.prevout.n >= len(txFrom.vout):
        raise VerifySignatureError("txin prevout.n >= len(txFrom.vout)")
    txout = txFrom.vout[txin.prevout.n]

    if txin.prevout.hash != txFrom.GetTxid():
        raise VerifySignatureError("prevout hash does not match txFrom")

    witness = None
    if txTo.wit:
        witness = txTo.wit.vtxinwit[inIdx].scriptWitness

    VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, inIdx,
                 amount=txout.nValue, witness=witness or CScriptWitness([]))


# --- RAWBIT PATCH START: convenience wrapper with tracing --------------
def VerifyScriptWithTrace(
    scriptSig: CScript,
    scriptPubKey: CScript,
    txTo: 'bitcointx.core.CTransaction',
    inIdx: int,
    flags: Optional[Union[Tuple[ScriptVerifyFlag_Type, ...],
                          Set[ScriptVerifyFlag_Type]]] = None,
    amount: int = 0,
    witness: Optional[CScriptWitness] = None,
    spent_outputs: Optional[Sequence['bitcointx.core.CTxOut']] = None
) -> Tuple[bool, List[TraceStep], Optional[str]]:
    """
    Verify like VerifyScript, but collect per-opcode trace steps.

    Returns: (is_valid: bool, steps: List[TraceStep], error_message: Optional[str])
    """
    steps: List[TraceStep] = []

    def _record(step: TraceStep) -> None:
        steps.append(step)

    try:
        # Argument checks mirror VerifyScript
        ensure_isinstance(scriptSig, CScript, 'scriptSig')
        if not isinstance(scriptPubKey, CScript):
            return False, steps, "scriptPubKey must be a CScript"
        if type(scriptSig) is not type(scriptPubKey):
            return False, steps, "scriptSig and scriptPubKey must be the same script class"

        script_class = scriptSig.__class__

        # Flags normalization
        if flags is None:
            flags = STANDARD_SCRIPT_VERIFY_FLAGS - UNHANDLED_SCRIPT_VERIFY_FLAGS
        else:
            flags = set(flags)

        if flags & UNHANDLED_SCRIPT_VERIFY_FLAGS:
            bad = script_verify_flags_to_string(flags & UNHANDLED_SCRIPT_VERIFY_FLAGS)
            return False, steps, f"some of the flags cannot be handled by current code: {bad}"

        if SCRIPT_VERIFY_SIGPUSHONLY in flags and not scriptSig.is_push_only():
            return False, steps, "scriptSig is not push-only"

        # Execute scriptSig
        stack: List[bytes] = []
        execdata = ScriptExecutionData()
        try:
            EvalScript(stack, scriptSig, txTo, inIdx, flags=flags, on_step=_record,
                       phase="scriptSig", execdata=execdata, spent_outputs=spent_outputs)
        except Exception as e:
            return False, steps, str(e)

        # P2SH stack copy
        if SCRIPT_VERIFY_P2SH in flags:
            stackCopy = list(stack)

        # Execute scriptPubKey
        try:
            EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags, on_step=_record,
                       phase="scriptPubKey", execdata=execdata, spent_outputs=spent_outputs)
        except Exception as e:
            return False, steps, str(e)

        if not stack:
            return False, steps, "scriptPubKey left an empty stack"
        if not _CastToBool(stack[-1]):
            return False, steps, "scriptPubKey returned false"

        hadWitness = False
        if witness is None:
            witness = CScriptWitness([])

        # Witness program
        if SCRIPT_VERIFY_WITNESS in flags and scriptPubKey.is_witness_scriptpubkey():
            hadWitness = True
            if scriptSig:
                return False, steps, "scriptSig is not empty"
            try:
                VerifyWitnessProgram(witness,
                                     scriptPubKey.witness_version(),
                                     scriptPubKey.witness_program(),
                                     txTo, inIdx, flags=flags, amount=amount,
                                     script_class=script_class,
                                     on_step=_record,
                                     spent_outputs=spent_outputs,
                                     execdata=execdata)
            except Exception as e:
                return False, steps, str(e)
            # Bypass cleanstack after witness
            stack = stack[:1]

        # P2SH branch
        if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
            if not scriptSig.is_push_only():
                return False, steps, "P2SH scriptSig not is_push_only()"

            stack = stackCopy
            if not stack:
                return False, steps, "P2SH stack empty after scriptSig"

            pubKey2 = script_class(stack.pop())
            try:
                EvalScript(stack, pubKey2, txTo, inIdx, flags=flags, on_step=_record,
                           phase="redeemScript", execdata=execdata, spent_outputs=spent_outputs)
            except Exception as e:
                return False, steps, str(e)

            if not stack:
                return False, steps, "P2SH inner scriptPubKey left an empty stack"
            if not _CastToBool(stack[-1]):
                return False, steps, "P2SH inner scriptPubKey returned false"

            # P2SH-wrapped witness
            if SCRIPT_VERIFY_WITNESS in flags and pubKey2.is_witness_scriptpubkey():
                hadWitness = True
                if scriptSig != script_class([pubKey2]):
                    return False, steps, "scriptSig is not exactly a single push of the redeemScript"
                try:
                    VerifyWitnessProgram(witness,
                                         pubKey2.witness_version(),
                                         pubKey2.witness_program(),
                                         txTo, inIdx, flags=flags, amount=amount,
                                         script_class=script_class,
                                         on_step=_record,
                                         spent_outputs=spent_outputs,
                                         execdata=execdata,
                                         is_p2sh_wrapped=True)
                except Exception as e:
                    return False, steps, str(e)
                stack = stack[:1]

        # CLEANSTACK
        if SCRIPT_VERIFY_CLEANSTACK in flags:
            if SCRIPT_VERIFY_P2SH not in flags:
                return False, steps, "SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_P2SH"
            if len(stack) != 1:
                return (False, steps,
                        f"scriptPubKey left {len(stack)} items on stack (cleanstack requires exactly 1)")

        # Unexpected witness data
        if SCRIPT_VERIFY_WITNESS in flags and not hadWitness and witness:
            return False, steps, "Unexpected witness"

        return True, steps, None

    except Exception as e:
        # Any uncaught exception
        return False, steps, str(e)
# --- RAWBIT PATCH END ---------------------------------------------------


__all__ = (
    'MAX_STACK_ITEMS',
    'SCRIPT_VERIFY_P2SH',
    'SCRIPT_VERIFY_STRICTENC',
    'SCRIPT_VERIFY_DERSIG',
    'SCRIPT_VERIFY_LOW_S',
    'SCRIPT_VERIFY_NULLDUMMY',
    'SCRIPT_VERIFY_SIGPUSHONLY',
    'SCRIPT_VERIFY_MINIMALDATA',
    'SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS',
    'SCRIPT_VERIFY_CLEANSTACK',
    'SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY',
    'SCRIPT_VERIFY_CHECKSEQUENCEVERIFY',
    'SCRIPT_VERIFY_TAPROOT',
    'SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION',
    'SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS',
    'SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE',
    'SCRIPT_VERIFY_FLAGS_BY_NAME',
    'ScriptExecutionData',
    'EvalScriptError',
    'MaxOpCountError',
    'MissingOpArgumentsError',
    'ArgumentsInvalidError',
    'VerifyOpFailedError',
    'EvalScript',
    'VerifyScriptError',
    'VerifyScript',
    'VerifySignatureError',
    'VerifySignature',
    'script_verify_flags_to_string',
    # --- RAWBIT PATCH: exports
    'VerifyScriptWithTrace',
)
