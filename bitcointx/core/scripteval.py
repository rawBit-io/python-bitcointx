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
from typing import (
    Iterable, Optional, List, Tuple, Set, Type, TypeVar, Union, Callable, TypedDict
)

import bitcointx.core
import bitcointx.core._bignum
import bitcointx.core.key
import bitcointx.core.serialize
import bitcointx.core._ripemd160

from bitcointx.util import ensure_isinstance

from bitcointx.core.script import (
    # Script helpers & containers
    CScript, CScriptOp, CScriptWitness, CScriptInvalidError,
    OPCODE_NAMES, DISABLED_OPCODES,
    FindAndDelete, IsLowDERSignature,
    SIGVERSION_Type, SIGVERSION_BASE, SIGVERSION_WITNESS_V0,

    # SIGHASH flags
    SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,

    # Size / opcode limits
    MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_OPCODES, MAX_SCRIPT_SIZE,

    # Signature opcodes
    OP_CHECKSIG, OP_CHECKSIGVERIFY,
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
    OP_PUSHDATA4,
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

_STRICT_ENCODING_FLAGS = set((SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_LOW_S, SCRIPT_VERIFY_STRICTENC))

# --- RAWBIT PATCH START: we handle CLTV/CSV, so they are not "unhandled"
UNHANDLED_SCRIPT_VERIFY_FLAGS = set((
    SCRIPT_VERIFY_SIGPUSHONLY,
    SCRIPT_VERIFY_MINIMALDATA,
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
    SCRIPT_VERIFY_TAPROOT
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


# --- RAWBIT PATCH START: CLTV / CSV helpers ----------------------------
def _CheckLockTimeVerify(stack, txTo, inIdx, flags, get_eval_state):
    """BIP-65  –  OP_CHECKLOCKTIMEVERIFY"""
    if len(stack) < 1:
        raise MissingOpArgumentsError(get_eval_state(), expected_stack_depth=1)

    nLockTime = _CastToBigNum(stack[-1], get_eval_state)
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

    nSequence = _CastToBigNum(stack[-1], get_eval_state)
    if nSequence < 0:
        raise EvalScriptError("negative sequence", get_eval_state())

    # disabled flag means "anyone-can-spend" in CSV context
    if nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        return

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
                         # --- RAWBIT PATCH START: tracing hook -----------
                         on_step: Optional[Callable[[dict], None]] = None
                         # --- RAWBIT PATCH END ---------------------------
                         ) -> None:

    if script_class is None:
        raise ValueError("script class must be specified")

    sigversion = None

    if witversion == 0:
        sigversion = SIGVERSION_WITNESS_V0
        stack = list(witness.stack)
        if len(program) == 32:
            # Version 0 segregated witness program: SHA256(CScript) inside the program,
            # CScript + inputs in witness
            if len(stack) == 0:
                raise VerifyScriptError("witness is empty")

            scriptPubKey = script_class(stack.pop())
            hashScriptPubKey = hashlib.sha256(scriptPubKey).digest()
            if hashScriptPubKey != program:
                raise VerifyScriptError("witness program mismatch")
        elif len(program) == 20:
            # Special case for pay-to-pubkeyhash; signature + pubkey in witness
            if len(stack) != 2:
                raise VerifyScriptError("witness program mismatch")  # 2 items in witness

            scriptPubKey = script_class([OP_DUP, OP_HASH160, program,
                                         OP_EQUALVERIFY, OP_CHECKSIG])
        else:
            raise VerifyScriptError("wrong length for witness program")
    elif SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in flags:
        raise VerifyScriptError("upgradeable witness program is not accepted")
    else:
        # Higher version witness scripts return true for future softfork compatibility
        return

    assert sigversion is not None

    for i, elt in enumerate(stack):
        if isinstance(elt, int):
            elt_len = len(script_class([elt]))
        else:
            elt_len = len(elt)

        # Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
        if elt_len > MAX_SCRIPT_ELEMENT_SIZE:
            raise VerifyScriptError(
                "maximum push size exceeded by an item at position {} "
                "on witness stack".format(i))

    # --- RAWBIT PATCH: forward tracing to inner script
    EvalScript(stack, scriptPubKey, txTo, inIdx,
               flags=flags, amount=amount, sigversion=sigversion,
               on_step=on_step, phase="witnessScript")

    # Scripts inside witness implicitly require cleanstack behaviour
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    elif len(stack) != 1:
        raise VerifyScriptError("scriptPubKey left extra items on stack")

    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    return


def _CastToBigNum(b: bytes, get_eval_state: Callable[[], ScriptEvalState]
                  ) -> int:
    if len(b) > MAX_NUM_SIZE:
        raise EvalScriptError('CastToBigNum() : overflow', get_eval_state())
    v = bitcointx.core._bignum.vch2bn(b)
    if v is None:
        raise EvalScriptError('CastToBigNum() : invalid value',
                              get_eval_state())
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
            # FIXME: this is incorrect, but not caught by existing
            # test cases
            stack.append(b"\x00")


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
                phase: str = "script"
                # --- RAWBIT PATCH END ----------------------------------
                ) -> None:
    """Evaluate a script

    """
    if len(scriptIn) > MAX_SCRIPT_SIZE:
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
    v_bool: bool
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
            if sop in DISABLED_OPCODES:
                raise EvalScriptError(f'opcode {_opcode_name(sop)} is disabled',
                                      get_eval_state())

            if sop > OP_16:
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
                    stack.append(sop_data)
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
                    tmpScript = scriptIn.__class__(scriptIn[pbegincodehash:])
                    _CheckMultiSig(sop, tmpScript, stack, txTo, inIdx, flags,
                                   get_eval_state, nOpCount,
                                   amount=amount, sigversion=sigversion)

                elif sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
                    check_args(2)
                    vchPubKey = stack[-1]
                    vchSig = stack[-2]

                    # Subset of script starting at the most recent codeseparator
                    tmpScript = scriptIn.__class__(scriptIn[pbegincodehash:])

                    if sigversion == SIGVERSION_BASE:
                        # Drop the signature in pre-segwit scripts but not segwit scripts
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
                            # FIXME: this is incorrect, but not caught by existing
                            # test cases
                            stack.append(b"\x00")

                elif sop == OP_CODESEPARATOR:
                    pbegincodehash = sop_pc

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

                        if sigversion == SIGVERSION_WITNESS_V0 and SCRIPT_VERIFY_MINIMALIF in flags:
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
                        # FIXME: this is incorrect, but not caught by existing
                        # test cases
                        stack.append(b"\x00")

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
               phase: str = "script"
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
                    sigversion=sigversion, on_step=on_step, phase=phase)
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
                 amount: int = 0, witness: Optional[CScriptWitness] = None
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

    if flags & UNHANDLED_SCRIPT_VERIFY_FLAGS:
        raise VerifyScriptError(
            "some of the flags cannot be handled by current code: {}"
            .format(script_verify_flags_to_string(flags & UNHANDLED_SCRIPT_VERIFY_FLAGS)))

    stack: List[bytes] = []
    EvalScript(stack, scriptSig, txTo, inIdx, flags=flags, phase="scriptSig")
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags, phase="scriptPubKey")
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
                             script_class=script_class)

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

        EvalScript(stack, pubKey2, txTo, inIdx, flags=flags, phase="redeemScript")

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
                                 script_class=script_class)

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
    witness: Optional[CScriptWitness] = None
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

        # Execute scriptSig
        stack: List[bytes] = []
        try:
            EvalScript(stack, scriptSig, txTo, inIdx, flags=flags, on_step=_record, phase="scriptSig")
        except Exception as e:
            return False, steps, str(e)

        # P2SH stack copy
        if SCRIPT_VERIFY_P2SH in flags:
            stackCopy = list(stack)

        # Execute scriptPubKey
        try:
            EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags, on_step=_record, phase="scriptPubKey")
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
                                     on_step=_record)
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
                EvalScript(stack, pubKey2, txTo, inIdx, flags=flags, on_step=_record, phase="redeemScript")
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
                                         on_step=_record)
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
    'SCRIPT_VERIFY_FLAGS_BY_NAME',
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
