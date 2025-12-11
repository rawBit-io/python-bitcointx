# Taproot Test Coverage Plan for python-bitcointx (v3)

## Overview

**Goal:** Add comprehensive Taproot (BIP-340/341/342) test coverage using ~230 curated tests instead of the 3,737-test qa-assets file.

**Principle:** Each phase must pass completely before moving to the next. This isolates failures and makes debugging tractable.

**Key insight:** The 8MB `script_assets_test.json` is a regression/fuzzing corpus, not a development test suite. Using it for TDD is like debugging a compiler using the entire Linux kernel source.

---

## Phase 1: BIP-340 Schnorr Primitives (~20 tests)

### Spec Coverage

- BIP-340: Verification algorithm
- BIP-340: Batch verification (if supported)
- BIP-340: Public key generation
- BIP-340: Signing algorithm (for round-trip tests)

### Source

- `bip-0340/test-vectors.csv` (19 official vectors)

### File

- `test_bip340_schnorr.py`

### Test Cases

| #   | Category         | Description                                | Expected |
| --- | ---------------- | ------------------------------------------ | -------- |
| 1-5 | Valid signatures | Vectors 0-4 from BIP-340                   | Pass     |
| 6   | Invalid pubkey   | x ≥ field prime (vector 14)                | Fail     |
| 7   | Invalid pubkey   | x doesn't lift to curve (vector 11)        | Fail     |
| 8   | Invalid pubkey   | x doesn't lift to curve (vector 12)        | Fail     |
| 9   | Invalid sig      | has_even_y(R) is false (vector 6)          | Fail     |
| 10  | Invalid sig      | Negated message (vector 7)                 | Fail     |
| 11  | Invalid sig      | Negated s value (vector 8)                 | Fail     |
| 12  | Invalid sig      | s ≥ curve order                            | Fail     |
| 13  | Edge case        | Infinite point trap (vector 9)             | Fail     |
| 14  | Edge case        | Infinite point trap (vector 10)            | Fail     |
| 15  | Edge case        | sG - eP is infinite (vector 14)            | Fail     |
| 16  | Invalid pubkey   | 32 zero bytes (not on curve)               | Fail     |
| 17  | Signing          | aux_rand=0 reproduces vector sig           | Pass     |
| 18  | Signing          | Round-trip sign then verify                | Pass     |
| 19  | Tagged hash      | Verify SHA256(tag) midstate precomputation | Pass     |
| 20  | lift_x           | Specific lift_x failure cases              | Fail     |

### Success Criteria

- All 19 BIP-340 vectors pass
- Schnorr verify returns correct bool for each case
- No crashes on malformed inputs
- Tagged hash implementation matches BIP-340 spec

---

## Phase 2: BIP-341 Construction (~55 tests)

### Spec Coverage

- BIP-341: "Constructing and spending Taproot outputs"
- BIP-341: TapTweak hash
- BIP-341: TapLeaf hash
- BIP-341: TapBranch hash
- BIP-341: Control block structure

### Source

- `bip-0341/wallet-test-vectors.json`

### File

- `test_bip341_construction.py`

### Test Cases

**Key Tweaking (10 tests)**

| #   | Description                                                   | Expected            |
| --- | ------------------------------------------------------------- | ------------------- |
| 1   | Tweak with empty script tree (key-path only): tweak = hash(P) | Pass                |
| 2   | Tweak with single leaf: tweak = hash(P \|\| merkle_root)      | Pass                |
| 3   | Tweak with balanced 2-leaf tree                               | Correct merkle root |
| 4   | Tweak with unbalanced 3-leaf tree                             | Correct merkle root |
| 5   | taproot_tweak_pubkey matches BIP vector                       | Pass                |
| 6   | taproot_tweak_seckey matches BIP vector                       | Pass                |
| 7   | Tweak is reversible with secret key                           | Pass                |
| 8   | Zero internal key (invalid)                                   | Fail                |
| 9   | Internal key not on curve                                     | Fail                |
| 10  | Parity bit calculation matches y-coordinate mod 2             | Pass                |

**TapLeaf Hashing (6 tests)**

| #   | Description                                                           | Expected           |
| --- | --------------------------------------------------------------------- | ------------------ |
| 11  | Single OP_CHECKSIG script                                             | Matches BIP vector |
| 12  | Empty script                                                          | Valid hash         |
| 13  | Maximum script size                                                   | Valid hash         |
| 14  | Leaf version 0xc0                                                     | Correct tagging    |
| 15  | Leaf version 0xc2 (future)                                            | Correct tagging    |
| 16  | Tagged hash structure: SHA256(SHA256(tag) \|\| SHA256(tag) \|\| data) | Pass               |

**TapBranch Hashing (6 tests)**

| #   | Description                      | Expected                  |
| --- | -------------------------------- | ------------------------- |
| 17  | Two leaves (lexicographic order) | Sorted concatenation      |
| 18  | Two leaves (reverse order input) | Same result (sorted)      |
| 19  | Nested branches                  | Recursive hashing correct |
| 20  | Single leaf (no branch)          | Root = leaf hash          |
| 21  | Deep tree (8 leaves)             | Correct root              |
| 22  | Unbalanced tree                  | Correct path lengths      |

**Merkle Root (8 tests)**

| #   | Description                    | Expected              |
| --- | ------------------------------ | --------------------- |
| 23  | Single leaf → root = leaf hash | Pass                  |
| 24  | Two leaves                     | Matches BIP vector    |
| 25  | Three leaves (unbalanced)      | Matches BIP vector    |
| 26  | Four leaves (balanced)         | Pass                  |
| 27  | Huffman-optimal tree from BIP  | Matches vector        |
| 28  | Empty tree (key-path only)     | No merkle root        |
| 29  | Maximum depth (128 levels)     | Valid                 |
| 30  | Depth 129                      | Invalid (exceeds max) |

**Control Block (10 tests)**

| #   | Description                          | Expected          |
| --- | ------------------------------------ | ----------------- |
| 31  | Single leaf: length = 33             | Pass              |
| 32  | Depth 3: length = 33 + 32\*3 = 129   | Pass              |
| 33  | Maximum depth: length = 33 + 32\*128 | Pass              |
| 34  | Parity bit = 0 (even y)              | Correct           |
| 35  | Parity bit = 1 (odd y)               | Correct           |
| 36  | Internal key encoding                | 32 bytes x-only   |
| 37  | Merkle path element order            | Matches spec      |
| 38  | Wrong length (34 bytes)              | Invalid           |
| 39  | Wrong length (32 bytes, too short)   | Invalid           |
| 40  | Leaf version in control byte         | Correctly encoded |

**scriptPubKey (6 tests)**

| #   | Description                 | Expected |
| --- | --------------------------- | -------- |
| 41  | Format: OP_1 <32-byte key>  | Pass     |
| 42  | Witness version = 1         | Pass     |
| 43  | Witness program = 32 bytes  | Pass     |
| 44  | Matches BIP-341 test vector | Pass     |
| 45  | Key-path only output        | Valid    |
| 46  | Script-path output          | Valid    |

**Bech32m Address (9 tests)**

| #   | Description                 | Expected |
| --- | --------------------------- | -------- |
| 47  | Mainnet prefix (bc1p...)    | Pass     |
| 48  | Testnet prefix (tb1p...)    | Pass     |
| 49  | Signet prefix (tb1p...)     | Pass     |
| 50  | Regtest prefix (bcrt1p...)  | Pass     |
| 51  | Checksum validation         | Pass     |
| 52  | Bech32m (not Bech32) for v1 | Pass     |
| 53  | Round-trip encode/decode    | Pass     |
| 54  | Invalid checksum detection  | Fail     |
| 55  | Case insensitivity          | Pass     |

### Success Criteria

- All BIP-341 wallet vectors pass
- Generated addresses match BIP examples exactly
- Control blocks have correct structure
- Empty vs non-empty merkle root tweaking both work

---

## Phase 3: Key-Path Spending & Sighash Core (~32 tests)

### Spec Coverage

- BIP-341: "Signature validation rules"
- BIP-341: "Common signature message" (SigMsg)
- BIP-341: "Key path spending"
- BIP-341: "Signature opcodes" (SIGHASH types)

### Source

- BIP-341 `keyPathSpending` vectors + handcrafted

### File

- `test_taproot_keypath.py`

### Key Concept: SIGHASH_DEFAULT vs SIGHASH_ALL

**Important:** These have _different_ digests. Per BIP-341, `hash_type` is the first byte of `SigMsg`. DEFAULT uses 0x00, ALL uses 0x01. They commit to the same transaction parts but the digests differ, so signatures are NOT interchangeable.

### Test Cases

**Hashtype Tests (12 tests)**

| #   | Hashtype                                      | Description                                                      | Expected        |
| --- | --------------------------------------------- | ---------------------------------------------------------------- | --------------- |
| 1   | DEFAULT (0x00)                                | 64-byte sig, no trailing byte                                    | Pass            |
| 2   | ALL (0x01)                                    | 65-byte sig with 0x01 suffix                                     | Pass            |
| 3   | DEFAULT vs ALL                                | Both commit to full tx; digests differ; sigs NOT interchangeable | Fail if swapped |
| 4   | DEFAULT sig used as ALL                       | Must fail verification                                           | Fail            |
| 5   | ALL sig used as DEFAULT                       | Must fail verification                                           | Fail            |
| 6   | NONE (0x02)                                   | Outputs not committed                                            | Pass            |
| 7   | SINGLE (0x03)                                 | Only corresponding output                                        | Pass            |
| 8   | ALL\|ANYONECANPAY (0x81)                      | Only signing input committed                                     | Pass            |
| 9   | NONE\|ANYONECANPAY (0x82)                     | Neither other inputs nor outputs                                 | Pass            |
| 10  | SINGLE\|ANYONECANPAY (0x83)                   | One input, one output                                            | Pass            |
| 11  | SINGLE with no corresponding output           | Must fail (BIP-341 rule)                                         | Fail            |
| 12  | Multi-input tx, different hashtypes per input | Each input independent                                           | Pass            |

**Invalid Hashtype Tests (4 tests)**

| #   | Hashtype | Description                  | Expected |
| --- | -------- | ---------------------------- | -------- |
| 13  | 0x04     | Undefined                    | Fail     |
| 14  | 0x11     | Undefined                    | Fail     |
| 15  | 0x80     | ANYONECANPAY alone (invalid) | Fail     |
| 16  | 0xff     | Invalid                      | Fail     |

**Signature Length Tests (5 tests)**

| #   | Length   | Description                            | Expected |
| --- | -------- | -------------------------------------- | -------- |
| 17  | 64 bytes | Valid (implies DEFAULT)                | Pass     |
| 18  | 65 bytes | Valid (explicit hashtype in last byte) | Pass     |
| 19  | 63 bytes | Invalid, too short                     | Fail     |
| 20  | 66 bytes | Invalid, too long                      | Fail     |
| 21  | 0 bytes  | Invalid for key-path                   | Fail     |

**Annex Tests (6 tests)**

| #   | Description                                                                     | Expected                |
| --- | ------------------------------------------------------------------------------- | ----------------------- |
| 22  | No annex: witness = [sig], has_annex = 0                                        | Pass                    |
| 23  | With annex: witness = [sig, <0x50...>], has_annex = 1                           | Pass                    |
| 24  | Sig made without annex, spent with annex present                                | Fail (different digest) |
| 25  | Sig made with annex, spent without annex                                        | Fail (different digest) |
| 26  | Single element starting with 0x50: NOT annex (need ≥2 elements), treated as sig | Fail (bad sig)          |
| 27  | Annex = just 0x50 (1 byte)                                                      | Valid annex format      |

**Mixed Transaction Tests (5 tests)**

| #   | Description                                       | Expected                     |
| --- | ------------------------------------------------- | ---------------------------- |
| 28  | Taproot + legacy inputs in same tx                | Independent validation       |
| 29  | Taproot + SegWit v0 inputs in same tx             | Independent validation       |
| 30  | Input index > 0                                   | Correct prevouts commitment  |
| 31  | Multiple Taproot inputs, different hashtypes      | Each validates independently |
| 32  | Key-path sighash matches BIP-341 reference vector | Pass                         |

### Success Criteria

- All hashtypes produce correct (distinct) digests per BIP-341
- DEFAULT and ALL signatures are NOT interchangeable
- Invalid hashtypes rejected at validation
- Annex presence/absence correctly affects sighash
- Signature length validation works
- Mixed transaction types don't interfere

---

## Phase 4: Script-Path Basics (~42 tests)

### Spec Coverage

- BIP-341: "Script path spending"
- BIP-341: "Leaf version" handling
- BIP-341: Control block verification
- BIP-341: Witness stack interpretation (key-path vs script-path)
- BIP-342: Basic script execution (CHECKSIG, CHECKSIGVERIFY)
- BIP-342: MINIMALIF (consensus rule)
- BIP-342: Clean stack requirement

### Source

- BIP-341 scriptPathSpending vectors + handcrafted

### File

- `test_taproot_scriptpath.py`

### Key Concept: Leaf Version Calculation

Per BIP-341: `leaf_version = c[0] & 0xfe` (mask off parity bit)

- `c[0] = 0xc0` → `v = 0xc0` → **tapscript (BIP-342)**
- `c[0] = 0xc1` → `v = 0xc0` → **tapscript (BIP-342)** (parity bit = 1)
- `c[0] = 0xc2` → `v = 0xc2` → **unknown/future** (not tapscript)
- `c[0] = 0xe0` → `v = 0xe0` → **unknown/future**

### Key Concept: Witness Stack Interpretation

Per BIP-341, after removing annex (if present):

- **Exactly 1 element** → key-path (element is signature)
- **≥2 elements** → script-path (last = control block, second-to-last = script)

There is no "script-path with 1 element" or "key-path with 2 elements".

### Test Cases

**Control Block Validation (10 tests)**

| #   | Description                                             | Expected |
| --- | ------------------------------------------------------- | -------- |
| 1   | Valid control block (single leaf, c[0]=0xc0)            | Pass     |
| 2   | Valid control block (depth 3)                           | Pass     |
| 3   | Wrong control block length (34 bytes, not 33+32\*m)     | Fail     |
| 4   | Wrong control block length (32 bytes, too short)        | Fail     |
| 5   | Wrong parity bit (even y but c[0]=0xc1)                 | Fail     |
| 6   | Internal key not on curve (lift_x fails)                | Fail     |
| 7   | Wrong Merkle path element (bit flip)                    | Fail     |
| 8   | Correct tree, wrong leaf script provided                | Fail     |
| 9   | Maximum depth (128): control block = 33 + 32\*128 bytes | Pass     |
| 10  | Depth 129 (exceeds max)                                 | Fail     |

**Witness Stack Interpretation (6 tests)**

| #   | Description                                                                   | Expected                        |
| --- | ----------------------------------------------------------------------------- | ------------------------------- |
| 11  | 1 element after annex removal → key-path                                      | Validates as signature          |
| 12  | 2 elements, last not 0x50 prefix → script-path                                | Attempts script-path validation |
| 13  | 2 elements, last has 0x50 prefix → annex removed, 1 element left → key-path   | First element is signature      |
| 14  | 3 elements, last has 0x50 prefix → annex removed, 2 left → script-path        | Normal script-path              |
| 15  | 2 elements, last not 0x50, invalid control block length → Fail as script-path | Fail (bad control block)        |
| 16  | Empty witness (0 elements)                                                    | Fail                            |

**Leaf Version Handling (6 tests)**

| #   | Description                                                                    | Expected                   |
| --- | ------------------------------------------------------------------------------ | -------------------------- |
| 17  | Control byte = 0xc0: v = 0xc0 → BIP-342 tapscript executed                     | Execute script             |
| 18  | Control byte = 0xc1: v = 0xc0 (parity=1) → BIP-342 tapscript executed          | Execute script             |
| 19  | Control byte = 0xc2: v = 0xc2 → unknown version, succeeds after Taproot checks | Pass (no script exec)      |
| 20  | Control byte = 0xe0: v = 0xe0 → unknown version                                | Pass (no script exec)      |
| 21  | Unknown version (0xc2) with garbage/unparseable script                         | Pass (script not parsed)   |
| 22  | Unknown version (0xc2) with OP_CHECKMULTISIG in script                         | Pass (script not executed) |

**Basic Tapscript Execution (8 tests)**

| #   | Description                                                       | Expected                            |
| --- | ----------------------------------------------------------------- | ----------------------------------- |
| 23  | Single CHECKSIG (valid sig)                                       | Pass                                |
| 24  | Single CHECKSIG (invalid sig)                                     | Fail                                |
| 25  | CHECKSIGVERIFY (valid sig)                                        | Pass                                |
| 26  | CHECKSIGVERIFY (invalid sig)                                      | Fail                                |
| 27  | Two CHECKSIG in sequence                                          | Both must verify                    |
| 28  | Script-path sighash differs from key-path (tapleaf_hash included) | Not interchangeable                 |
| 29  | Script-path sighash includes tapleaf_hash                         | Pass                                |
| 30  | Empty signature in CHECKSIG                                       | Returns 0 (false), script continues |

**MINIMALIF Consensus Tests (5 tests)**

| #   | Description                | Expected                           |
| --- | -------------------------- | ---------------------------------- |
| 31  | IF with empty vector (0x)  | False branch taken, pass           |
| 32  | IF with 0x01               | True branch taken, pass            |
| 33  | IF with 0x02               | Fail (not minimal, consensus rule) |
| 34  | IF with 0x0100 (two bytes) | Fail (not minimal)                 |
| 35  | NOTIF with same rules      | Same behavior                      |

**Clean Stack & CastToBool (7 tests)**

| #   | Description                                  | Expected                  |
| --- | -------------------------------------------- | ------------------------- |
| 36  | Script ends with single true element (0x01)  | Pass                      |
| 37  | Script ends with single non-zero byte (0x42) | Pass                      |
| 38  | Script ends with two elements                | Fail (not clean stack)    |
| 39  | Script ends with single 0x00                 | Fail (CastToBool = false) |
| 40  | Script ends with empty vector                | Fail (CastToBool = false) |
| 41  | Script ends with 0x00000000 (4 zero bytes)   | Fail                      |
| 42  | Script ends with 0x80 (negative zero)        | Fail                      |

### Success Criteria

- Control block validation catches all invalid cases
- Witness stack correctly interpreted as key-path vs script-path
- Unknown leaf versions succeed without executing script
- MINIMALIF enforced as consensus (not just standardness)
- Basic tapscript CHECKSIG/CHECKSIGVERIFY work
- Clean stack + CastToBool enforced correctly

---

## Phase 5a: Validation Weight Budget (~15 tests)

### Spec Coverage

- BIP-342: "Resource limits"
- BIP-342: "Sigops budget"

### Formula

```
budget = 50 + total_witness_size_bytes (including CompactSize prefix)
```

Each signature opcode with non-empty signature: -50
Empty signature: 0 cost

### Rationale

The 97 `sigopsratio` failures are likely a single missing feature. Isolating this before other tapscript specifics makes debugging clearer.

### Source

- Handcrafted + curated qa-assets subset

### File

- `test_tapscript_budget.py`

### Test Cases

**Budget Calculation (6 tests)**

| #   | Description                                         | Expected |
| --- | --------------------------------------------------- | -------- |
| 1   | budget = 50 + witness_size (verify formula)         | Pass     |
| 2   | CHECKSIG with non-empty sig consumes 50 units       | Pass     |
| 3   | CHECKSIGVERIFY with non-empty sig consumes 50 units | Pass     |
| 4   | CHECKSIGADD with non-empty sig consumes 50 units    | Pass     |
| 5   | Empty signature consumes 0 units                    | Pass     |
| 6   | Witness padding increases budget proportionally     | Pass     |

**Budget Boundary Tests (6 tests)**

| #   | Description                                            | Expected |
| --- | ------------------------------------------------------ | -------- |
| 7   | sigops \* 50 == budget exactly                         | Pass     |
| 8   | sigops \* 50 == budget + 1 (one over)                  | Fail     |
| 9   | Multiple sigops, total exactly at limit                | Pass     |
| 10  | Multiple sigops, one unit over limit                   | Fail     |
| 11  | Large witness (more budget), many sigops within budget | Pass     |
| 12  | Small witness (less budget), too many sigops           | Fail     |

**Unknown Pubkey Budget (3 tests)**

| #   | Description                                    | Expected           |
| --- | ---------------------------------------------- | ------------------ |
| 13  | 33-byte pubkey, non-empty sig: still counts 50 | Consumes 50 units  |
| 14  | 33-byte pubkey, empty sig: doesn't count       | Consumes 0 units   |
| 15  | Multiple unknown pubkeys with non-empty sigs   | Cumulative 50 each |

### Success Criteria

- Budget calculated correctly: 50 + witness_size
- Each non-empty signature consumes 50 units
- Empty signatures consume 0 units
- Unknown pubkey types still consume budget (if non-empty sig)
- Budget exhaustion fails script immediately

---

## Phase 5b: Tapscript Semantics (~40 tests)

### Spec Coverage

- BIP-342: "Script execution"
- BIP-342: "OP_CHECKSIGADD"
- BIP-342: "OP_SUCCESSx"
- BIP-342: "Rules for signature opcodes"
- BIP-342: "CODESEPARATOR"
- BIP-342: "Disabled opcodes"
- BIP-342: Removed limits (script size, opcode count)

### Source

- Handcrafted + curated qa-assets subset

### File

- `test_tapscript.py`

### Test Cases

**OP_CHECKSIGADD (10 tests)**

| #   | Description                                                        | Expected |
| --- | ------------------------------------------------------------------ | -------- |
| 1   | Basic increment: 0 <sig> <pk> CSA → stack = [1]                    | Pass     |
| 2   | No increment: 0 <empty> <pk> CSA → stack = [0]                     | Pass     |
| 3   | Invalid sig fails script immediately (not returns 0)               | Fail     |
| 4   | 2-of-3: exactly 2 valid sigs → pass                                | Pass     |
| 5   | 2-of-3: only 1 valid sig → fail (NUMEQUAL mismatch)                | Fail     |
| 6   | 2-of-3: 2 sigs but one invalid → fail (sig verification)           | Fail     |
| 7   | 3-of-3: all valid                                                  | Pass     |
| 8   | Accumulator > 4 bytes (CScriptNum overflow)                        | Fail     |
| 9   | Unknown pubkey (33-byte), non-empty sig: increments, counts sigops | Pass     |
| 10  | Unknown pubkey (33-byte), empty sig: no increment, no sigops       | Pass     |

**OP_SUCCESS Short-Circuit (8 tests)**

| #   | Description                                                | Expected                       |
| --- | ---------------------------------------------------------- | ------------------------------ |
| 11  | OP_SUCCESS80 (0x50) alone                                  | Pass immediately               |
| 12  | OP_SUCCESS in unreachable IF branch                        | Still pass (scanned at decode) |
| 13  | OP_SUCCESS with trailing garbage bytes                     | Pass (not parsed beyond)       |
| 14  | OP_SUCCESS followed by invalid opcode bytes                | Pass                           |
| 15  | OP_SUCCESS in script that would fail clean-stack           | Pass (bypasses check)          |
| 16  | OP_SUCCESS in script that would exceed sigops budget       | Pass (bypasses check)          |
| 17  | OP_SUCCESS in script with disabled opcode after it         | Pass                           |
| 18  | Multiple OP_SUCCESS opcodes (0x50, 0x62, 0x89, 0xba, 0xfe) | All pass                       |

**OP_SUCCESS vs Similar Opcodes (3 tests)**

| #   | Description                                   | Expected                   |
| --- | --------------------------------------------- | -------------------------- |
| 19  | OP_NOP (0x61) is NOT OP_SUCCESS               | Normal execution continues |
| 20  | OP_NOP10 (0xb9) is NOT OP_SUCCESS             | Normal execution continues |
| 21  | OP_RESERVED (0x50) IS OP_SUCCESS in tapscript | Pass immediately           |

**Unknown Pubkey Types (6 tests)**

| #   | Description                                                       | Expected |
| --- | ----------------------------------------------------------------- | -------- |
| 22  | CHECKSIG, 33-byte pk, non-empty sig → skip verify, push 1         | Pass     |
| 23  | CHECKSIG, 33-byte pk, empty sig → push 0                          | Pass     |
| 24  | CHECKSIG, 20-byte pk, non-empty sig → skip verify, push 1         | Pass     |
| 25  | CHECKSIG, 0-byte pk, non-empty sig → fail (special case)          | Fail     |
| 26  | CHECKSIG, 0-byte pk, empty sig → fail (special case)              | Fail     |
| 27  | CHECKSIGVERIFY, 33-byte pk, non-empty sig → skip verify, continue | Pass     |

**CODESEPARATOR (6 tests)**

| #   | Description                                               | Expected                 |
| --- | --------------------------------------------------------- | ------------------------ |
| 28  | No CODESEPARATOR executed: codesep_pos = 0xFFFFFFFF       | Pass                     |
| 29  | CODESEPARATOR before CHECKSIG: codesep_pos = byte offset  | Pass                     |
| 30  | Multiple CODESEPARATOR: last executed one sets pos        | Pass                     |
| 31  | CODESEPARATOR in unexecuted IF branch: pos unchanged      | Pass                     |
| 32  | Same script with/without CODESEPARATOR: different sighash | Sigs not interchangeable |
| 33  | Position is byte offset in script, not opcode index       | Pass                     |

**Script-Path Sighash Variations (4 tests)**

| #   | Description                                                                 | Expected                 |
| --- | --------------------------------------------------------------------------- | ------------------------ |
| 34  | Script-path with SIGHASH_DEFAULT (0x00)                                     | Pass, matches BIP-341    |
| 35  | Script-path with SIGHASH_SINGLE\|ANYONECANPAY (0x83)                        | Pass                     |
| 36  | Script-path with annex vs without: different digest                         | Sigs not interchangeable |
| 37  | Script-path sighash includes ext (tapleaf_hash + key_version + codesep_pos) | Pass                     |

**Disabled Opcodes (4 tests)**

| #   | Description                                    | Expected            |
| --- | ---------------------------------------------- | ------------------- |
| 38  | OP_CHECKMULTISIG (0xae) in executed path       | Fail immediately    |
| 39  | OP_CHECKMULTISIGVERIFY (0xaf) in executed path | Fail immediately    |
| 40  | OP_CHECKMULTISIG in non-taken IF branch        | Pass (not executed) |
| 41  | OP_CHECKMULTISIGVERIFY in non-taken IF branch  | Pass (not executed) |

**Removed Limits (4 tests)**

| #   | Description                                                         | Expected |
| --- | ------------------------------------------------------------------- | -------- |
| 42  | Script size > 10,000 bytes (e.g., 10,500 bytes of OP_NOP + OP_TRUE) | Pass     |
| 43  | Script with > 201 non-push opcodes (e.g., 250 × OP_NOP)             | Pass     |
| 44  | Same >10k script in P2WSH would fail (for comparison, if testable)  | Fail     |
| 45  | Same >201 opcode script in P2WSH would fail (for comparison)        | Fail     |

**CScriptNum Strictness (3 tests)**

| #   | Description                                          | Expected |
| --- | ---------------------------------------------------- | -------- |
| 46  | Minimal encoding required for CHECKSIGADD input      | Pass     |
| 47  | Non-minimal CScriptNum (leading zero) in CHECKSIGADD | Fail     |
| 48  | Non-minimal negative number encoding                 | Fail     |

### Success Criteria

- OP_CHECKSIGADD accumulator logic correct
- Invalid signature fails script (not just returns 0)
- OP_SUCCESS short-circuits unconditionally before all other checks
- Unknown pubkey types handled per BIP-342
- CODESEPARATOR position correctly tracked
- Script-path sighash with all hashtypes and annex variations
- Disabled opcodes fail only when executed
- 10,000 byte and 201 opcode limits NOT enforced in tapscript
- CScriptNum strictness enforced (inherited from MINIMALDATA)

---

## Phase 6: Edge Cases & Error Handling (~28 tests)

### Spec Coverage

- BIP-341: Error conditions
- BIP-342: Error conditions
- BIP-341: Non-Taproot witness v1 handling
- Resource limits (stack + altstack)

### Source

- Curated qa-assets subset + handcrafted

### File

- `test_taproot_errors.py`

### Test Cases

**Invalid x-only Pubkeys in Spends (4 tests)**

Note: These are _spend_ tests, not output creation tests. An output with invalid x can be created but never successfully spent.

| #   | Description                                                  | Expected            |
| --- | ------------------------------------------------------------ | ------------------- |
| 1   | Spend P2TR output where x ≥ field prime: any signature fails | Fail                |
| 2   | Control block internal key x doesn't lift to curve           | Fail                |
| 3   | Script contains 32-byte pubkey that doesn't lift             | Fail at CHECKSIG    |
| 4   | x-only pubkey = 32 zero bytes                                | Fail (not on curve) |

**Witness Structure Errors (6 tests)**

| #   | Description                                                                  | Expected              |
| --- | ---------------------------------------------------------------------------- | --------------------- |
| 5   | Empty witness (0 elements)                                                   | Fail                  |
| 6   | 2 elements, last not 0x50: script-path attempted, fails on bad control block | Fail                  |
| 7   | 2 elements, both invalid: neither valid key-path nor script-path             | Fail                  |
| 8   | 3+ elements forming invalid script-path                                      | Fail                  |
| 9   | Valid annex format but invalid signature                                     | Fail                  |
| 10  | Maximum witness stack size at limit                                          | Pass/Fail at boundary |

**Signature Errors (5 tests)**

| #   | Description                    | Expected |
| --- | ------------------------------ | -------- |
| 11  | Signature with s = 0           | Fail     |
| 12  | Signature with R not on curve  | Fail     |
| 13  | Signature for wrong message/tx | Fail     |
| 14  | Truncated signature (32 bytes) | Fail     |
| 15  | Oversized signature (67 bytes) | Fail     |

**Script Errors (5 tests)**

| #   | Description                              | Expected |
| --- | ---------------------------------------- | -------- |
| 16  | Stack underflow in tapscript             | Fail     |
| 17  | OP_RETURN in tapscript                   | Fail     |
| 18  | Disabled opcode (CHECKMULTISIG) executed | Fail     |
| 19  | Push exceeds 520 bytes                   | Fail     |
| 20  | Stack size > 1000 elements               | Fail     |

**Stack + Altstack Resource Limit (3 tests)**

| #   | Description                                           | Expected |
| --- | ----------------------------------------------------- | -------- |
| 21  | Stack near 1000, altstack empty: passes               | Pass     |
| 22  | Stack + altstack combined > 1000                      | Fail     |
| 23  | Initial witness stack + script pushes > 1000 combined | Fail     |

**Non-Taproot Witness v1 Outputs (5 tests)**

Per BIP-341: Taproot rules apply ONLY when witness version = 1 AND program length = 32. Other v1 outputs are "unencumbered" (not Taproot).

| #   | Description                                             | Expected                           |
| --- | ------------------------------------------------------- | ---------------------------------- |
| 24  | Witness v1, program length = 20 bytes                   | NOT Taproot, no Taproot validation |
| 25  | Witness v1, program length = 31 bytes                   | NOT Taproot                        |
| 26  | Witness v1, program length = 33 bytes                   | NOT Taproot                        |
| 27  | Witness v1, program length = 40 bytes                   | NOT Taproot                        |
| 28  | Verify Taproot code path NOT entered for non-32-byte v1 | Pass                               |

### Success Criteria

- All invalid inputs rejected with appropriate error
- No crashes or hangs on malformed data
- Non-Taproot v1 outputs correctly identified and not processed as Taproot
- Stack + altstack limit enforced
- Error messages are meaningful

---

## Phase 7: Full qa-assets Regression (Optional, ~3700 tests)

### Source

- `script_assets_test.json`

### File

- `test_script_assets.py`

### Configuration

```python
@pytest.mark.slow
@pytest.mark.parametrize("test_case", load_script_assets())
def test_script_assets(test_case):
    """Full Bitcoin Core script_assets_test.json regression."""
    ...
```

### Running

```bash
# Normal development (skip slow)
pytest bitcointx/tests/

# Full regression (CI nightly)
pytest bitcointx/tests/ --run-slow

# Pre-release (mandatory)
TAPROOT_FULL_ASSETS=1 pytest bitcointx/tests/
```

### Progress Tracking

After each phase completes, re-run full qa-assets to measure improvement:

| Milestone              | Expected Pass Rate | Notes                                 |
| ---------------------- | ------------------ | ------------------------------------- |
| Baseline (before work) | 95.0% (3548/3737)  | Initial state                         |
| After Phase 3          | ~96.5%             | Sighash fixes (~56 failures resolved) |
| After Phase 4          | ~97.0%             | Unknown leaf version (~10 resolved)   |
| After Phase 5a         | ~99.5%             | Sigops budget (~97 resolved)          |
| After Phase 5b         | ~99.8%             | OP_SUCCESS, disabled opcodes          |
| After Phase 6          | 100%               | All edge cases                        |

### Success Criteria

- All 189 original failures fixed
- Target: 100% pass rate
- No regressions in pre-Taproot tests

---

## Test File Structure

```
bitcointx/tests/
├── test_script_vectors.py            # Existing pre-Taproot (1209 tests)
│
├── data/
│   ├── bip340_test_vectors.csv       # Phase 1 (19 vectors)
│   ├── bip341_wallet_vectors.json    # Phase 2 (~50 vectors)
│   └── script_assets_test.json       # Phase 7 (3737 vectors, optional)
│
├── test_bip340_schnorr.py            # Phase 1: ~20 tests
├── test_bip341_construction.py       # Phase 2: ~55 tests
├── test_taproot_keypath.py           # Phase 3: ~32 tests
├── test_taproot_scriptpath.py        # Phase 4: ~42 tests
├── test_tapscript_budget.py          # Phase 5a: ~15 tests
├── test_tapscript.py                 # Phase 5b: ~48 tests
├── test_taproot_errors.py            # Phase 6: ~28 tests
└── test_script_assets.py             # Phase 7: ~3700 tests (slow)
```

---

## Test Count Summary

| Phase | File                        | Tests | Cumulative |
| ----- | --------------------------- | ----- | ---------- |
| 1     | test_bip340_schnorr.py      | ~20   | 20         |
| 2     | test_bip341_construction.py | ~55   | 75         |
| 3     | test_taproot_keypath.py     | ~32   | 107        |
| 4     | test_taproot_scriptpath.py  | ~42   | 149        |
| 5a    | test_tapscript_budget.py    | ~15   | 164        |
| 5b    | test_tapscript.py           | ~48   | 212        |
| 6     | test_taproot_errors.py      | ~28   | 240        |
| 7     | test_script_assets.py       | ~3700 | (optional) |

**Total curated tests: ~240**

---

## Execution Rules

1. **Sequential phases:** Complete Phase N before starting Phase N+1
2. **Green before proceeding:** All tests in a phase must pass
3. **Fix forward:** If a phase fails, fix the code, don't skip tests
4. **Measure progress:** After each phase, run full qa-assets to track improvement
5. **Add derived tests:** If qa-assets catches something curated tests miss, add one targeted test
6. **Document coverage:** Each phase lists which BIP sections it covers

---

## Root Cause → Phase Mapping

Based on initial failure analysis:

| Root Cause                    | Failures | Phase | Fix Complexity       |
| ----------------------------- | -------- | ----- | -------------------- |
| Validation weight budget      | 97       | 5a    | Medium (new feature) |
| Sighash computation bugs      | 56       | 3     | Medium (debugging)   |
| OP_SUCCESS short-circuit      | 10       | 5b    | Low (control flow)   |
| Unknown leaf version          | 10       | 4     | Low (control flow)   |
| Invalid hashtype not rejected | 7        | 3     | Low (validation)     |
| Other edge cases              | 9        | 6     | Varies               |

---

## Consensus Rules Checklist

### BIP-340 (Phase 1)

- [ ] Valid Schnorr signature verification
- [ ] Invalid R (not on curve, infinity)
- [ ] Invalid s (≥ curve order)
- [ ] Invalid pubkey (not on curve, ≥ field)
- [ ] Edge cases (vectors 9-14)
- [ ] Tagged hash implementation
- [ ] lift_x failures

### BIP-341 (Phases 2-4)

- [ ] Key tweaking (internal → output)
- [ ] Empty merkle root tweak: hash(P)
- [ ] Non-empty merkle root tweak: hash(P || root)
- [ ] TapLeaf/TapBranch hashing
- [ ] Merkle root construction
- [ ] Control block structure (33 + 32\*m)
- [ ] Control block parity bit
- [ ] Control block max depth (128)
- [ ] Internal key validation
- [ ] Leaf version calculation: v = c[0] & 0xfe
- [ ] Leaf version 0xc0/0xc1 → tapscript
- [ ] Unknown leaf versions → success without script execution
- [ ] scriptPubKey format (OP_1 <32 bytes>)
- [ ] Bech32m address encoding
- [ ] Witness interpretation: 1 element = key-path, ≥2 = script-path
- [ ] Annex detection (0x50 prefix, ≥2 elements before removal)
- [ ] Key-path sighash (all hashtypes, distinct digests)
- [ ] Script-path sighash (ext with tapleaf_hash, key_version, codesep_pos)
- [ ] SIGHASH_DEFAULT ≠ SIGHASH_ALL (different digests)
- [ ] Invalid hashtype rejection
- [ ] Annex in sighash (has_annex bit, sha_annex)
- [ ] Signature length validation (64 or 65 only)
- [ ] Non-Taproot v1 (length ≠ 32) not processed as Taproot

### BIP-342 (Phases 4-6)

- [ ] CHECKSIG in tapscript
- [ ] CHECKSIGVERIFY in tapscript
- [ ] OP_CHECKSIGADD accumulator
- [ ] OP_CHECKSIGADD: invalid sig fails script (not returns 0)
- [ ] OP_CHECKSIGADD: CScriptNum limits on accumulator
- [ ] OP_SUCCESS short-circuit (before all other validation)
- [ ] OP_SUCCESS with trailing garbage
- [ ] OP_SUCCESS bypasses clean stack, sigops, everything
- [ ] Unknown pubkey types: size ≠ 0 and ≠ 32 → skip verification
- [ ] Unknown pubkey: non-empty sig → success, counts sigops
- [ ] Unknown pubkey: empty sig → push 0, no sigops
- [ ] 0-byte pubkey: always fails
- [ ] MINIMALIF as consensus (not just standardness)
- [ ] CODESEPARATOR position tracking (byte offset)
- [ ] Sigops budget: 50 + witness_size
- [ ] Sigops budget: 50 per non-empty sig
- [ ] Sigops budget: 0 for empty sig
- [ ] Empty signature in CHECKSIG → push 0, continue
- [ ] Clean stack requirement (exactly 1 element)
- [ ] CastToBool on final element
- [ ] Disabled opcodes: CHECKMULTISIG, CHECKMULTISIGVERIFY
- [ ] Removed limits: >10,000 byte scripts allowed
- [ ] Removed limits: >201 opcodes allowed
- [ ] Stack + altstack ≤ 1000 elements
- [ ] CScriptNum minimal encoding enforced

---

## Implementation Notes

### Python-Specific Gotchas

1. **Integer Encoding (CScriptNum)**

   - Tapscript enforces minimal encoding (inherited from MINIMALDATA)
   - Test non-minimal inputs explicitly
   - Note: This is existing behavior, not new in BIP-342

2. **Tagged Hashes**

   - `SHA256(SHA256(tag) || SHA256(tag) || data)`
   - Pre-compute midstate for efficiency
   - Verify against BIP-340 test vectors

3. **Variable Length Ints**

   - Control block parsing uses VarInts
   - Ensure robust parsing of edge cases

4. **Signature Parsing**

   - 64 bytes = SIGHASH_DEFAULT (0x00)
   - 65 bytes = explicit hashtype in last byte
   - Other lengths = immediate failure

5. **Leaf Version Masking**
   - `v = control_block[0] & 0xfe`
   - Don't confuse control byte with leaf version
   - 0xc0 and 0xc1 both → v = 0xc0 (tapscript)

### Cross-Validation

For handcrafted vectors not from BIPs:

- Consider cross-checking against `bitcoind` via RPC
- Or compare with `feature_taproot.py` expected values
- Document the validation method for each test

---

## References

- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP-342: Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [BIP-340 Test Vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv)
- [BIP-341 Wallet Vectors](https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json)
- [Bitcoin Core qa-assets](https://github.com/bitcoin-core/qa-assets)
- [Bitcoin Core feature_taproot.py](https://github.com/bitcoin/bitcoin/blob/master/test/functional/feature_taproot.py)
