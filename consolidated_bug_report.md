# rawBit `python-bitcointx` fork — Consolidated Bug Report

**Date:** 2026-07-13
**Commit range audited:** `0b881f75ccdfecb6e6df3cdc7cb2d93bab7ec2cd` → `435e481b6fbc76c0cd52e484685e4cf4283e1a61` (18 commits)
**Baseline:** `a40643f…` (upstream python‑bitcointx 1.1.5, parent of `0b881f7`)
**Downstream:** rawBit `@ 880c30e` — pins this fork by exact commit SHA in `requirements-special.txt`

## About this document

This merges three prior audits into one deduplicated, adjudicated worklist:

| Source | Content |
|---|---|
| `claude_bug_check1.md` | Claude audit — findings **C1, H1–H4, M1–M16, L1–L8** + info |
| `codex_bug_check1.md` (= `fable_check.md`, identical) | Codex audit — findings **F‑01 … F‑27** |
| `reviiew_1_2.md` | Two cross‑reviews reconciling the above (severity corrections, non‑issues, omissions) |

Every behavioral finding here was **reproduced dynamically** against the working tree at `435e481` unless marked otherwise. Where the two audits disagreed on severity or on whether something is a bug, the cross‑review adjudication has been applied and the reasoning noted inline. Each entry carries its source IDs so you can trace back.

### Severity model
| Tier | Meaning |
|---|---|
| **P0** | Validation verdict can differ from Bitcoin consensus in the **accepting** direction (accepts a script/tx the network rejects). |
| **P1** | Crash on valid data, consensus **rejecting**‑direction divergence, broken primary‑API contract, public‑service availability risk, or an assurance gate that can hide consensus regressions. |
| **P2** | Standardness/policy‑flag mismatch, incomplete/misleading trace on the primary feature, packaging, or test laxity. |
| **P3** | Minor robustness, typing, docs, error‑precedence, metadata, ergonomics. |

---

## 1. Master index

| ID | Sev | Title | Location | Sources |
|---|---|---|---|---|
| **B01** | P0 | SegWit‑v0 `OP_CODESEPARATOR` off‑by‑one → wrong BIP143 scriptCode (**accepts network‑invalid / rejects valid**) | `scripteval.py:1547` | C1 · F‑01 |
| **B02** | P1 | CSV version gate compares **signed** `nVersion` → rejects Core‑valid txs (version ≥ 0x80000000) | `scripteval.py:540` | H1 |
| **B03** | P1 | BIP143 packs `nLockTime` as signed `<i` → **crashes** on locktimes ≥ 0x80000000 (post‑2038 timelocks) | `script.py:1353` | F‑03 |
| **B04** | P1 | Library‑internal exceptions escape `VerifyScript` on craftable witnesses (3 genuine causes) | `scripteval.py:837/874`, `script.py:1550` | H3 · F‑22 |
| **B05** | P1 | secp256k1 `seckey_negate` not aliased → `CKey.negated()/sub()` broken; test edit masks it | `secp256k1.py:217`, `test_key.py:79` | H4 · F‑09 |
| **B06** | P1 | Unbounded trace memory → DoS for the public app (80 KB tapscript → 50 MB; no tapscript size limit) | `scripteval.py:1312/1358`, `2173` | M1 · F‑08 |
| **B07** | P1 | Malformed `leaf_version` trace event **crashes** rawBit’s React viewer (`.startsWith(undefined)`) | `scripteval.py:858` | M7 · F‑07 |
| **B08** | P1 | `VerifyScriptWithTrace` drops the `WITNESS ⇒ P2SH` guard → returns `True` where `VerifyScript` raises (**rawBit‑reachable**) | `scripteval.py:2168` | M9 · F‑06 |
| **B09** | P2 | Signatureless tapscript (`OP_TRUE`/OP_SUCCESS) unnecessarily requires `spent_outputs` | `scripteval.py:870` | F‑02 |
| **B10** | P1 | CI has never run (`branches: [ $default-branch ]`) and would use an unpinned/empty libsecp256k1 version | `.github/workflows/main.yml:5,34` | F‑04 |
| **B11** | P2 | `_CheckSig` empty‑sig early return skips STRICTENC/WITNESS_PUBKEYTYPE pubkey checks | `scripteval.py:952` | M2 · F‑10 |
| **B12** | P2 | Missing Core‑v30 pay‑to‑anchor carve‑out → intended empty-witness P2A spend rejected by default | `scripteval.py:906` | H2 · F‑12 |
| **B13** | P2 | Native v1‑32B with `TAPROOT` unset + discourage rejected; Core returns success | `scripteval.py:712` | M3 · F‑11 |
| **B14** | P2 | Disabled CLTV/CSV + `DISCOURAGE_UPGRADABLE_NOPS` rejected; Core treats assigned CLTV/CSV as plain NOPs | `scripteval.py:1649‑1667` | F‑13 |
| **B15** | P2 | Trace shows opcodes in **unexecuted** IF/ELSE branches as ordinary executed steps | `scripteval.py:1772` | M4 · F‑15 |
| **B16** | P2 | Key Taproot trace `step` identifiers don’t match rawBit → curated explanations never fire | `scripteval.py:754` | M6 · F‑17 |
| **B17** | P2 | Many invalid results emit no terminal `failed:true` step (662/1493 corpus failures) | `scripteval.py:853` | M8 · F‑16 |
| **B18** | P2 | Trace blanket `except Exception` flattens library‑internal errors into “script failed” | `scripteval.py:2173` | M10 · F‑17 |
| **B19** | P2 | Trace omits OP_SUCCESS short‑circuit and annex processing events | `scripteval.py:873`, `725` | F‑17 · info |
| **B20** | P2 | `tests_core` harness treats `CLEANSTACK` ≡ `EVAL_FALSE` (14 vectors), hiding error‑identity divergence | `test_script_vectors.py:367` | M13 · F‑21 |
| **B21** | P1 | QA harness converts valid-case regressions to runtime `pytest.xfail` + dedups by comment; 70 vectors are not strict gates | `test_taproot_keypath.py:233`, `test_scripteval.py:131` | M14 · M15 · F‑05 · F‑21 |
| **B22** | P2 | Taproot trace events have **zero** test coverage despite four dedicated commits | `test_scripteval_trace.py` | M16 |
| **B23** | P2 | rawBit hides 3 active Taproot policy flags; user cannot toggle them | rawBit `calc_func.py` | F‑18 |
| **B24** | P2 | Built wheel ships legacy tests without their data (data-backed tests fail at runtime) and omits the new `tests_core` suite | `setup.py:33`, `MANIFEST.in` | F‑20 · info |
| **B25** | P2 | `SCRIPT_VERIFY_CONST_SCRIPTCODE` unimplemented + Claude’s proposed fix is incomplete | `scripteval.py:150` | L1 · F‑14 |
| **B26** | P3 | `OP_CHECKSIGADD` (0xba) missing from `OPCODE_NAMES` → “unknown opcode” in traces | `script.py` OPCODE_NAMES | F‑26 |
| **B27** | P2 | Advertised Python 3.7 cannot import the tracer because `typing.TypedDict` is 3.8+ | `setup.py:31`, `scripteval.py:24` | L2 · F‑19 |
| **B28** | P2 | 73.3% of `script_assets` entries are not executed; comment dedup drops 746/799 Phase‑4 candidates | `test_taproot_scriptpath.py:63` | L3 · F‑05 |
| **B29** | P3 | `plan.md` claims test files/coverage that don’t exist (Phase 5b/7) | `plan.md:744` | L4 · F‑27 |
| **B30** | P3 | `witness_script` trace event emitted before control‑block/tweak/leaf‑version validation | `scripteval.py:809` | L5 |
| **B31** | P3 | A raising `on_step` callback produces a bogus duplicate `failed` step and can mask the original exception | `scripteval.py:1782` | L6 |
| **B32** | P3 | Trace-path pre-checks diverge; both entry points also omit `CLEANSTACK ⇒ WITNESS` | `scripteval.py:2064`, `2161` | L7 · L8 · F‑25 |
| **B33** | P3 | `VerifyWitnessProgram` positional callback compatibility silently broken (`on_step` shifted) | `scripteval.py:559‑573` | F‑23 |
| **B34** | P3 | `VerifySignature` cannot verify Taproot spends (no `spent_outputs`) | `scripteval.py:1994` | F‑24 |
| **B35** | P3 | `OP_CHECKSIGADD` empty/unknown‑pubkey checks run before the sigops‑budget decrement, unlike Core | `scripteval.py:1509` | F‑25 |
| **B36** | P3 | `TraceStep` typing is `total=False` (no real contract); public trace types not exported | `scripteval.py:1223` | F‑23 |
| **B37** | P3 | rawBit filters every `phase=="witness"` validator step from the interactive/copied trace | rawBit `ScriptExecutionSteps.tsx` | F‑26 |
| **B38** | P3 | Fork metadata/README/release‑notes/vector‑provenance don’t describe the fork accurately | `setup.py:31`, README, `release-notes.md`, vectors | F‑27 |

**Not bugs / reclassified** (adjudicated in §6): Claude **M12** (SegWit‑v0 amount vs `spent_outputs`) is *by design*; Claude **M11** (spent_outputs consistency) is optional app‑side hardening, not a verifier defect; Claude **M5** (data pushes named “unknown opcode”) is *by design per the pinned integration contract* (rawBit normalizes it) — the real omission is B26.

---

## 2. P0 — Critical

### B01 — SegWit‑v0 `OP_CODESEPARATOR` builds the wrong BIP143 scriptCode
**`scripteval.py:1546‑1547`** · sources **C1 / F‑01** · reproduced by both audits (identical conclusion) · **inherited from the baseline**; `0b881f7` preserved/moved the existing assignment

```python
elif sop == OP_CODESEPARATOR:
    pbegincodehash = sop_pc          # byte offset OF the 0xab opcode, not one past it
```

`raw_iter()` yields `sop_pc` = the index of the `OP_CODESEPARATOR` byte. Bitcoin Core sets `pbegincodehash = pc` **after** advancing past the opcode, so the consensus scriptCode is `script[sop_pc+1:]`. The scriptCode used at `:1427`/`:1480` therefore begins with a stray `0xab`. For `SIGVERSION_BASE` this is masked (`FindAndDelete` strips separators symmetrically); for **`SIGVERSION_WITNESS_V0`** BIP143 serialises the scriptCode verbatim with no stripping, so the fork hashes a scriptCode one byte too long.

**Reproduced** (P2WSH `[…, OP_CODESEPARATOR, <pub>, OP_CHECKSIG]`): a signature over the **Core‑correct** scriptCode is **rejected**; a signature over the codesep‑inclusive scriptCode is **accepted** — a wrong‑accept of a network‑invalid spend, and the only wrong‑accept identified by this audit. The tapscript path is unaffected (it correctly uses `opcode_pos`).

**Fix (one line):** `pbegincodehash = sop_pc + 1`. Legacy is unchanged. Add regression tests: P2WSH CHECKSIG/CHECKMULTISIG with one executed separator; multiple separators (only the last counts); a separator in an unexecuted branch (must not set the slice point); the exact accept‑Core‑sig / reject‑fork‑sig pair.

---

## 3. P1 — High

### B02 — CSV version gate compares signed `nVersion`
**`scripteval.py:540‑541`** · source **H1** (Codex missed this) · reproduced · consensus divergence, fail‑closed

```python
if txTo.nVersion < 2:
    raise EvalScriptError("CSV requires transaction version >= 2", get_eval_state())
```

`CTransaction` stores `nVersion` as **signed** int32 (`core/__init__.py:1132`), so a tx whose raw version is `0xFFFFFFFF` has `nVersion == -1`. Core evaluates BIP‑68/112 on the **unsigned** value, so version `0xFFFFFFFF` (= 4294967295) **passes** the gate; the fork rejects it. Reproduced under both `SIGVERSION_WITNESS_V0` and `SIGVERSION_TAPSCRIPT`. Rare (nonstandard versions) but a genuine rule‑level divergence.

**Fix:** `if (txTo.nVersion & 0xFFFFFFFF) < 2:`

### B03 — BIP143 serialises `nLockTime` as signed → crash on valid locktimes
**`script.py:1353`** · source **F‑03** (Claude missed this) · reproduced · pre‑existing/inherited

```python
f.write(struct.pack("<i", txTo.nLockTime))     # BIP143 witness-v0 preimage
```

`nLockTime` is deserialised **unsigned** (`core/__init__.py:1172`, `<I`), but the BIP143 preimage packs it **signed** (`<i`). Any locktime in `0x80000000`…`0xffffffff` raises `struct.error` instead of producing a digest. This is reachable: locktime ≥ `0x80000000` is a **Unix‑time timelock past January 2038**, so any post‑2038 timelocked P2WPKH/P2WSH spend crashes the verifier (opaque failure in rawBit). The Taproot sighash path at `:1505` and legacy transaction serialization at `core/__init__.py:1190` already use unsigned `<I`.

**Fix:** `f.write(struct.pack("<I", txTo.nLockTime))`. Add boundary vectors for `0`, `0x7fffffff`, `0x80000000`, `0xffffffff`.

### B04 — Library‑internal exceptions escape `VerifyScript` instead of `ValidationError`
**`scripteval.py:837`, `:874`; `script.py:1550`** · sources **H3 / F‑22** · reproduced · API‑contract break + attacker‑triggerable crash

`VerifyScript` documents *“Raises a `ValidationError` subclass if the validation fails.”* Three **genuine** consensus‑invalid inputs instead leak a raw `ValueError`/`CScriptInvalidError` (verdict is still “reject”, but a caller doing `except ValidationError:` crashes on attacker‑suppliable witnesses):

1. **Invalid x‑only key in the control block** (`scripteval.py:834‑838`) — `check_tap_tweak` raises `ValueError('supplied internal_pub must be valid')`; Core returns `WITNESS_PROGRAM_MISMATCH`.
2. **Undecodable tapscript in the OP_SUCCESS pre‑scan** (`scripteval.py:874`) — `raw_iter()` raises `CScriptTruncatedPushDataError`; Core returns `BAD_OPCODE`.
3. **`SIGHASH_SINGLE` with no matching output** (`script.py:1548‑1551`, from `scripteval.py:758/1456/1528`) — raises `ValueError('outIdx … out of range')`; Core returns `SCHNORR_SIG_HASHTYPE`; BIP‑341 says *fail*, not *crash*.

> **Adjudication:** Claude’s H3 also listed a 4th cause — a `spent_outputs` length ≠ `vin` mismatch (`script.py:1482`). The cross‑review reclassifies that as **caller API misuse**, where a plain `ValueError` is reasonable (see B‑note under §6). Only the three above are contract violations.

**Fix:** handle the three causes narrowly. Validate/map an invalid x‑only internal key at the tweak site; catch only `CScriptInvalidError` around the OP_SUCCESS pre‑scan; and explicitly detect Taproot `SIGHASH_SINGLE` without a corresponding output before calling `SignatureHashSchnorr` (or introduce a dedicated exception/status for that condition). **Do not** broadly catch every `ValueError` from `SignatureHashSchnorr`: it also reports caller/API errors such as an invalid `inIdx` or the wrong number of `spent_outputs`, which §6 intentionally does not classify as script failure. This removes these three known leaks; B18 still needs explicit wrapper‑level exception classification.

### B05 — secp256k1 negation compat incomplete; test masks the break
**`secp256k1.py:217` + `test_key.py:79`** · sources **H4 / F‑09** · reproduced · underlying modern‑library compatibility gap inherited; masking test change introduced in this range

Commit `c6442ce` aliased `secp256k1_ec_privkey_tweak_add → seckey_tweak_add` but left the existing negate compatibility gap: it did **not** resolve `secp256k1_ec_privkey_negate → secp256k1_ec_seckey_negate`. On modern libsecp256k1 (Homebrew 0.6/0.7) `has_privkey_negate` is `False` and `CKey.negated()/sub()` raise `RuntimeError` even though `seckey_negate` is exported. Commit `984705d` then changed `test_key.py` to `skipTest(...)` on modern libs **and deleted the negative‑path assertions**, hiding the defect from that test on modern installations. The repository CI is independently broken under B10, and the pinned older libsecp build may still expose the legacy name.

**Fix:** resolve the old and new negate symbols through an **optional** binder, set `has_privkey_negate` from the resolved callable, and leave it `False` when neither symbol exists. Do not reuse a required binding helper that raises in the genuine “neither” case. Correct the backwards error message, restore the deleted `assertRaises` tests, add fake‑CDLL tests for old‑only/new‑only/both/neither, and test v0.4.0 + current v0.7.x in CI.

### B06 — Unbounded trace memory (DoS for the public app)
**`scripteval.py:1312/1358`, blanket catch `:2173`** · sources **M1 / F‑08** · reproduced · **P1 for a public service** (cross‑review)

Every opcode records a full hex snapshot of `stack_before`/`stack_after`. Legacy/v0 retain script/opcount limits, but traces can still be large when the initial witness stack is large; the earlier ~45 MB measurement is **not** a proven worst‑case bound. **Tapscript has no script-size or opcode-count limit**, so trace size is `O(script_size × stack_depth)` and is effectively bounded only by transaction/request size and available resources. **Reproduced:** a valid tapscript of `OP_1` + 40 000×`(OP_DUP OP_DROP)` (80 KB) → **80 006 steps, 50 MB** for one call; filling the stack to 1000×520‑byte items makes each snapshot ~1 MB → multi‑GB. rawBit always collects the full trace and accepts up to 5 MB request bodies; its time/size limits do not cap memory already allocated. The blanket `except Exception` can also catch and misclassify `MemoryError`, `RecursionError`, and rawBit’s signal-driven timeout exception; handling may itself fail under OOM, or the OS may kill the process first.

**Fix:** check `max_trace_steps`/`max_trace_bytes` **before constructing full hex stack snapshots**, then emit one bounded `trace_truncated` event; avoid copying unchanged stacks (deltas/lazy); enforce per‑request process/memory and independent input caps in rawBit; and explicitly re‑raise resource/timeout exceptions instead of classifying them as “invalid script.”

### B07 — Malformed `leaf_version` trace event crashes rawBit’s viewer
**`scripteval.py:857‑865`** · sources **M7 / F‑07** · reproduced · **P1 for rawBit** (cross‑review: it *crashes*, not just misrenders)

The unknown‑tapleaf event emits only `{'phase','step','leaf_version','policy'}` — the only event lacking `pc`, `kind`, `opcode_name`, and stacks. rawBit classifies a step as validator iff `kind=='validator' || pc<0`; with `pc` undefined, `undefined<0` is false, so it’s treated as an engine opcode: `opcodeExplanation()` receives `undefined` and calls `.startsWith()` on it, **throwing in the React trace dialog** (reproduced with the bundled `unkver/bare` vector).

**Fix:** emit the full schema — `"pc": -1, "kind": "validator", "opcode_name": "taproot_leaf_version"`, stack snapshots, and `failed:true`/`error` on policy rejection. Add a rawBit test that renders the actual Python‑emitted JSON, and make the frontend defensive against missing fields.

### B08 — Traced and untraced verifiers disagree (`WITNESS ⇒ P2SH` guard missing)
**`scripteval.py:2159‑2169` vs `:1978‑1984`** · sources **M9 / F‑06** · reproduced · **rawBit‑reachable** (cross‑review correction)

`VerifyScript` enforces that `SCRIPT_VERIFY_WITNESS` implies `SCRIPT_VERIFY_P2SH` (raises `ValueError`, mirroring Core’s `assert`). The hand‑copied `VerifyScriptWithTrace` omits this guard, so with `flags={WITNESS}` it returns `(True, …)` where `VerifyScript` raises — a tracing path changing the outcome. **Correction to Claude’s M9:** rawBit is *not* immune — it starts from standard flags and lets a user exclude `P2SH` and `CLEANSTACK` while keeping WITNESS (`calc_func.py:3268`), reaching exactly this divergence.

**Fix:** add the missing guard to the trace path immediately. The durable fix is to make `VerifyScript` and `VerifyScriptWithTrace` share **one** private verifier with an optional `on_step` callback. That creates one place to address B18/B32 but does not itself classify exceptions correctly.

### B10 — CI has never run; workflow is non‑reproducible
**`.github/workflows/main.yml:5,34`, `README.md:62`** · source **F‑04** · verified · assurance

The workflow filters on the literal placeholder `branches: [ $default-branch ]`, so pushes/PRs never trigger it (only manual dispatch). The libsecp256k1 version parser `grep -A1 '…MARKER…' README.md | tail -n 1` returns empty because `0b881f7` inserted a blank line after the marker, so a dispatched run would `git checkout` libsecp’s mutable default branch. Under the audit environment, the full suite reported **1,999 passed / 3 skipped / 3 xfailed / 67 xpassed**; `tests_core` accounted for **1,831 passed / 3 xfailed / 67 xpassed**. Flake8 rose from 0 baseline findings to 37, while mypy rose from 48 errors in 6 files to 89 in 13 files (the 41 net-new errors are all under `tests_core`). This leaves the fork without an automated gate; independently, B01 also needs a new regression vector because a functioning generic workflow would not discover an untested edge case by itself.

**Fix:** set the real branch (`master`); put `LIBSECP256K1_VERSION: v0.4.0` in config and fail if empty; add Python 3.12 and decide the support window; pin dev tools; split lint/types/build/tests/downstream into jobs; add a rawBit integration job; build+install wheel/sdist in a clean env.

### B21 — QA harness masks valid-case regressions (xfail + comment dedup + skips)
**`test_taproot_keypath.py:230‑234`, `test_taproot_scriptpath.py:91‑95`, `test_tapscript_budget.py:70‑74`, `test_scripteval.py:118‑132`** · sources **M14 · M15 · F‑05 · F‑21** · verified · **P1 assurance gate**

Three runners wrap expected-success `verify()` in `try/except Exception: pytest.xfail(…)`: a regression that rejects a Core-valid spend reports **xfail**, not failure. Expected-failure branches accept broad exceptions such as `ValueError`/`IndexError`, so an internal crash can count as the expected rejection; an unexpected acceptance still fails because the missed `pytest.raises` assertion is not caught.

The legacy harness silently skips 66 `UNKNOWN_ERROR` vectors plus 4 Taproot templates; `tests_core` marks the same 70 rows non-strict xfail and currently reports **67 XPASS / 3 XFAIL** for them. The selected `script_assets` cases currently trigger no runtime xfail when called directly, but the four templates remain unexpanded, so “all 70 pass directly” would be inaccurate. `test_taproot_errors.py` already demonstrates the correct fail-hard pattern.

**Fix:** replace runtime `xfail` with `fail`/`assert`; narrow expected rejection exceptions to `ValidationError`; run `UNKNOWN_ERROR` vectors while asserting rejection; expand the 4 Taproot templates via `TaprootScriptTree`; set `xfail_strict=true`; and assert collection counts plus vector checksums.

---

## 4. P2 — Medium

### B09 — Signatureless tapscript unnecessarily requires `spent_outputs`
**`scripteval.py:870‑871`** · source **F‑02** (Claude missed) · reproduced · **P2 API over‑strictness / rawBit UX limitation**

```python
if spent_outputs is None:
    raise VerifyScriptError("spent_outputs are required for tapscript verification")
```

This check sits **before** the OP_SUCCESS pre‑scan and execution, so an `OP_TRUE` leaf or a permitted OP_SUCCESS path — neither of which computes a sighash — is rejected without prevouts. This is a real false negative for the library API, but not a same-context network-consensus divergence: a validating node has the full UTXO context, while this API invocation does not. It is therefore fail‑closed and rated P2.

rawBit mirrors the restriction in its preflight (`calc_func.py:3347‑3363`). The visible limitation is primarily **multi-input P2TR**: for a single input rawBit fabricates `[CTxOut(amount, current_spk)]`, which is sufficient for signatureless execution because those fields are unused.

**Fix:** remove the global check at `:870‑871`; require prevouts only at sites that actually call `SignatureHashSchnorr` (key path, or a 32‑byte-key CHECKSIG/CHECKSIGADD with a non-empty signature). In rawBit, pass `None` when full context is unavailable and let the executed signature operation request it dynamically. Do **not** try to predict executed signature operations with a static script scan: branches, empty signatures, OP_SUCCESS, and future pubkey types make that unreliable.

### B11 — Empty signature bypasses pubkey‑encoding policy
**`scripteval.py:952‑953`** · sources **M2 / F‑10** · reproduced · policy‑flag (inherited)

`_CheckSig` returns `False` on an empty signature **before** the STRICTENC / WITNESS_PUBKEYTYPE pubkey checks (`:964‑976`). Core validates pubkey encoding independently of signature emptiness, so a malformed pubkey fails the script (`PUBKEYTYPE`). Because the fork enables STRICTENC by default, `0 <malformed-pubkey> CHECKSIG NOT` validates as **true** where Core policy fails. (Codex rated P1; consensus is unaffected, so P2 is the merged call.)

**Fix:** refactor so pubkey-encoding checks run first, then return `False` for an empty signature, and only then perform signature-specific indexing/DER/low-S checks. Do **not** mechanically move the return below code such as `sig[-1]`, which would turn the empty-signature case into an `IndexError`. The same ordering applies inside CHECKMULTISIG.

### B12 — Missing pay‑to‑anchor (P2A) carve‑out
**`scripteval.py:906‑909`** · sources **H2 / F‑12** · reproduced · **P2** (cross‑review downgraded from Claude’s P1: policy, not consensus)

Core v30 returns success for a native witness‑v1 2‑byte program `0x4e73` **before** the discourage check. The fork has no such branch, so under its default flags (which include `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`) the intended empty-witness spend of a P2A output is reported invalid while Core accepts it. P2A is used for TRUC ephemeral anchors and is relevant to potential Lightning commitment designs; deployed Lightning anchor outputs are not universally P2A.

**Fix:** before the discourage fallback — `if not is_p2sh_wrapped and witversion == 1 and program == b'\x4e\x73': return`. P2SH‑wrapped P2A must not get the exemption.

### B13 — Native v1‑32B with `TAPROOT` unset + discourage is rejected
**`scripteval.py:711‑715`** · sources **M3 / F‑11** · reproduced · flag‑dispatch (fail‑closed, narrow)

Core returns immediate success for a native v1‑32B program when `TAPROOT` is unset, bypassing the discourage check; the fork checks discourage first and rejects. Only reachable when a caller strips `TAPROOT` but keeps discourage. **Fix:** for `not is_p2sh_wrapped` v1‑32B, `if SCRIPT_VERIFY_TAPROOT not in flags: return` with no discourage check.

### B14 — Disabled CLTV/CSV rejected under `DISCOURAGE_UPGRADABLE_NOPS`
**`scripteval.py:1648‑1667`** · source **F‑13** · reproduced · directly confirmed against Core v30

When the CLTV/CSV verify flag is absent but `DISCOURAGE_UPGRADABLE_NOPS` is present, the fork rejects `OP_CHECKLOCKTIMEVERIFY`/`OP_CHECKSEQUENCEVERIFY` as reserved NOPs. Core v30 does **not**: those opcodes have their own case labels that `break` (plain NOP) when their flag is off; the discourage return lives only in the `OP_NOP1/NOP4‑NOP10` case. So Core accepts `<disabled CLTV> OP_1` here; the fork rejects. (Claude’s report incorrectly said DISCOURAGE_UPGRADABLE_NOPS “matches Core.”) Low real impact — rawBit’s standard flags enable CLTV/CSV — but a genuine gap.

**Fix:** remove the `elif DISCOURAGE_UPGRADABLE_NOPS: raise` branches for assigned CLTV/CSV (treat as NOP). Add an explicit NOP1–NOP10 + CLTV + CSV flag matrix.

### B15 — Inactive‑branch opcodes traced as executed
**`scripteval.py:1771‑1780`** · sources **M4 / F‑15** · reproduced · misleading trace

The end‑of‑loop `on_step` fires for every iterated opcode, including `fExec == False` ones, with no distinguishing field (`stack_before == stack_after`). `OP_0 OP_IF OP_RETURN OP_ENDIF OP_1` traces `OP_RETURN` as a step that apparently ran and didn’t fail — actively misleading in an educational debugger.

**Fix:** expose separate semantics such as `branch_active` and `processed`/`effect`, then render inactive ordinary opcodes distinctly. A single `executed: fExec` bit is insufficient because flow-control opcodes are structurally processed, and disabled/always-invalid opcodes have special behavior even while a branch is inactive.

### B16 — Taproot trace `step` identifiers don’t match rawBit
**`scripteval.py:750‑792`, `:840‑865`** · sources **M6 / F‑17** · reproduced · consumer‑contract mismatch

The fork emits `opcode_name='taproot_witness'|…` but `step='witness_stack'|'sighash'|…`. rawBit dispatches on `step.step ?? step.opcode_name`, so the `??` fallback never fires for those events and the key Taproot validator events land in the default branch — the curated BIP‑341/340 explanations are dead code; `control_block`/`leaf_version` have no case at all. The `witness_script` event is an exception: it already matches an existing rawBit switch case.

**Fix (adjudicated):** the integration contract *pins* these `step` names, so **don’t** silently rename library events. Prefer: rawBit accepts both old and canonical aliases, or introduce a **versioned trace schema** and migrate library + rawBit together. Add trace tests pinning the chosen values (see B22).

### B17 — Many invalid results emit no terminal `failed:true` step
**`scripteval.py:853` and across `VerifyWitnessProgram`** · sources **M8 / F‑16** · reproduced · incomplete trace

Only two sites emit a failure step (P2WSH program mismatch `:635`; per‑opcode `:1782`). Empty witness, wrong program length, element/stack limits, control‑block size, **tweak mismatch** (`:853`, whose `control_block` step carries `result:False` but not `failed:true`), invalid schnorr size/hashtype, OP_SUCCESS‑discouraged, and the final stack checks all emit no failure marker. Measured across the **entire bundled failure corpus**, **662 of 1,493 (44.3%)** failing executions had no `failed=True` event; that denominator is not limited to `VerifyWitnessProgram`. rawBit highlights failures via `failed:true`, so these collapse to a generic “Verification failed.” (Also: the `scriptPubKey returned false` message at `:707/:902` misnames the witnessScript.)

**Fix:** emit a `failed:true`/`error` validator step (with a stable machine `error_code`) at every non‑opcode boundary and set it on the `control_block` step when `tweak_ok` is false. Add a suite invariant: every `False` result has exactly one terminal failed event unless truncated.

### B18 — Trace blanket `except` flattens internal errors into “script failed”
**`scripteval.py:2077/2088/2114/2132/2155/2173`** · sources **M10 / F‑17** · reproduced · error classification

Every phase catches `Exception` and returns `(False, steps, str(e))`, so a genuine `ValidationError` rejection is indistinguishable from the library‑internal leaks of B04. Over a 4945‑case sweep, **36** cases rejected via a non‑`ValidationError` reported as a clean `ok=False` (0 acceptance flips, but classification is lost).

**Fix:** classify in the handlers — treat `ValidationError` (and narrowly mapped `CScriptInvalidError` cases that correspond to script failure) as a script failure; tag anything else as internal (prefix/`error_kind`) or re‑raise. B04 removes three known leaks, but sharing/refactoring the verifier does not automatically solve this wrapper-boundary classification problem.

### B19 — OP_SUCCESS and annex processing invisible in traces
**`scripteval.py:873/1315` (OP_SUCCESS), `:725‑730` (annex)** · source **F‑17 + Claude info** · reproduced

In the `VerifyWitnessProgram` pre-scan, OP_SUCCESS returns before a success event and leaves the trace ending at the control-block step. In direct `_EvalScript`, OP_SUCCESS also returns before emitting the opcode event, but there is no control-block event in that path. In both cases a spend valid *because of* OP_SUCCESS is unexplained. The annex is popped and hashed before the first Taproot event, so “Load witness stack” shows one fewer element and the annex/annex-hash that feed the sighash are never surfaced.

**Fix:** emit an `op_success` short‑circuit event (byte PC, opcode, policy, terminal result) before returning; emit the original witness first, then a `taproot_annex` event with `annex_hex` and the hash.

### B20 — `tests_core` treats `CLEANSTACK` ≡ `EVAL_FALSE`
**`test_script_vectors.py:365‑368`** · sources **M13 / F‑21** · reproduced · harness laxity

`_expected_matches()` accepts actual `EVAL_FALSE` for expected `CLEANSTACK`. Its comment correctly describes the current bitcointx/Core difference, but the phrase “when that flag is set” is wrong for witness execution: Core’s `ExecuteWitnessScript` returns `SCRIPT_ERR_CLEANSTACK` unconditionally whenever the final stack size ≠ 1 (including 0). **14** Core v30 vectors pass only via this equivalence — the implementation raises an empty-stack error where Core reports `CLEANSTACK`; the harness never notices.

**Fix:** make witness‑script final‑stack ≠ 1 raise a cleanstack‑classified error (unconditionally, per Core), fix the comment, delete the equivalence (and the unused `WITNESS_MALLEATED` alternates) so error identity is enforced.

### B22 — Zero test coverage for taproot trace events
**`test_scripteval_trace.py`** · source **M16** · verified · missing coverage on a flagship feature

Four commits added `taproot_witness`/`taproot_sighash`/`taproot_schnorr_verify`/`taproot_control_block`/`witness_script` emission, yet the only trace test file covers only legacy + v0. B16/B07 broke the consumer contract with no test failing.

**Fix:** add key‑path tests (sequence + fields) and script‑path tests (control‑block merkle/parity/leaf, witnessScript steps) with failure variants; assert the chosen `step` vocabulary (ties to B16).

### B23 — rawBit hides 3 active Taproot policy flags
**rawBit `calc_func.py:3185‑3204,3268‑3310`** · source **F‑18** · downstream

rawBit maintains a second, incomplete `FLAG_BY_NAME` that omits `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`, `DISCOURAGE_OP_SUCCESS`, `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`. All three are active in verification but not disclosed in `activeFlags` and can’t be excluded (“Unknown flag”), so consensus‑valid future‑leaf/OP_SUCCESS/future‑key examples are rejected by default and the UI can’t demonstrate consensus‑vs‑policy.

**Fix:** derive the backend map from `SCRIPT_VERIFY_FLAGS_BY_NAME`, assert every active flag has a display entry, add “consensus rules” vs “standard policy” presets, and normalize flag dependencies in one place.

### B24 — Packaging: broken installed tests, omitted conformance suite
**`setup.py:33‑37`, `MANIFEST.in`** · source **F‑20 + Claude info** · packaging

`find_packages()` ships `bitcointx.tests` but not its `data/`, so an installed `Test_EvalScript.test_script` fails with `FileNotFoundError` on `script_tests.json`. Conversely `bitcointx/tests_core` has no `__init__.py` and is absent from artifacts, so consumers can’t reproduce the new conformance claims.

**Fix:** pick one policy — ship all test data + `tests_core` (add `__init__.py`, `package_data`), or stop shipping test modules in wheels. Add CI that builds+installs wheel/sdist and smoke‑tests.

### B25 — `CONST_SCRIPTCODE` unimplemented; incomplete proposed fix
**`scripteval.py:150`** · sources **L1 / F‑14** · inherited standard-policy gap · **P2 under this report’s policy-mismatch rubric**

The flag is present in `STANDARD_…` but also `UNHANDLED_…`, so it is silently subtracted from defaults. Claude’s proposed fix (reject only *executed* `OP_CODESEPARATOR`) is incomplete: Core rejects a BASE `OP_CODESEPARATOR` **before branch execution** (including an unexecuted branch), and also rejects CHECKSIG/CHECKMULTISIG when `FindAndDelete` mutates scriptCode.

**Fix:** implement all three behaviors before removing the flag from `UNHANDLED_…`: unconditional BASE OP_CODESEPARATOR rejection, CHECKSIG mutation detection, and CHECKMULTISIG mutation detection. Add exact vectors. If full support is intentionally deferred, rename the displayed mode to “supported subset of standard policy.”

### B27 — Advertised Python 3.7 cannot import the tracer
**`setup.py:31`, `scripteval.py:24`** · sources **L2 / F‑19** · packaging/runtime contract · **P2**

`typing.TypedDict` is 3.8+, but metadata claims `>=3.7` (classifiers 3.7–3.12); importing `scripteval` on 3.7 fails.

**Fix:** bump to `>=3.8` and drop the 3.7 classifier, or import `TypedDict` from `typing_extensions` **and add the appropriate conditional runtime dependency**. Align the CI matrix with the chosen support window, including Python 3.12.

### B28 — 73.3% of `script_assets` entries are not executed
**`test_taproot_scriptpath.py:37,63`** · sources **L3 / F‑05** · corpus assurance gap · **P2**

The corpus contains **2,244 entries / 3,737 success+failure cases**. The committed selectors actually execute **600 unique entries / 1,197 cases**, leaving **1,644 entries (73.3%) / 2,540 cases (68.0%) unexecuted**. The previous “59% unexercised” figure conflated this with the narrower fact that **1,334 entries (59.4%) match no raw selector at all**.

In Phase 4, 819 prefix matches become 799 candidates after 20 `SKIP_CONTAINS=('undecodable',)` exclusions, then comment dedup executes only 53 and drops 746. In Phase 6, 118 matches become 29 executed and 89 deduped. An independent full audit ran all 3,737 cases successfully, but the committed suite does not enforce that result.

**Fix:** add a slow full-corpus test keyed by entry index rather than comment; remove `SKIP_CONTAINS`; assert collection counts and vector checksums.

---

## 5. P3 — Low

### B26 — `OP_CHECKSIGADD` named “unknown opcode”
**`script.py` `OPCODE_NAMES`** · source **F‑26** · verified (0xba absent). The central new BIP‑342 opcode traces as “unknown opcode.” This is the *real* naming omission (vs. Claude’s M5, which is by‑design for data pushes). **Fix:** add `OP_CHECKSIGADD` to `OPCODE_NAMES` and test it.

### B29 — `plan.md` claims nonexistent tests
**`plan.md:744‑755`** · sources **L4 / F‑27**. Lists `test_tapscript.py` (Phase 5b) and `test_script_assets.py` (Phase 7) that don’t exist; Phase 1/2 tables promise tests the files don’t contain. README is accurate. **Fix:** implement or add per‑phase status markers so it can’t be read as coverage.

### B30 — `witness_script` trace event emitted too early
**`scripteval.py:807‑818`** · source **L5**. Emitted after popping control/script but before the control-block size check, tweak verification, and leaf-version check; rawBit therefore harvests a candidate as `witnessScript` even when commitment validation later fails or an unknown-version leaf is deliberately not executed. The early event can still be useful failure context, so moving it outright would lose information. **Fix:** model separate states/events such as `candidate`, `committed`, and `executed` (or at minimum add those booleans), and have rawBit label them accurately.

### B31 — Raising `on_step` callback → bogus `failed` step
**`scripteval.py:1771‑1795`** · source **L6**. The success `on_step` sits inside the per‑opcode `try`; a raising callback re‑enters `on_step` marking the opcode `failed:true` with the callback’s own message, and a second raise replaces the original exception. **Fix:** move the success emission outside the `try`, or guard the failure emission and skip it when the exception came from the callback.

### B32 — Trace‑path pre‑check divergences
**`scripteval.py:2064‑2069`, `:2160‑2162`** · sources **L7 · L8 · F‑25**. `VerifyScriptWithTrace` checks unhandled flags before SIGPUSHONLY (opposite of `VerifyScript`), and returns `ok=False` for CLEANSTACK-without-P2SH where `VerifyScript` raises `ValueError` (API-misuse signal). In addition, Core requires CLEANSTACK to imply **both P2SH and WITNESS**; both fork entry points enforce only the P2SH dependency, and rawBit can exclude WITNESS while leaving CLEANSTACK active. These are invalid flag configurations/API-contract differences, not transaction acceptance divergences. **Fix:** add the missing CLEANSTACK ⇒ WITNESS check immediately; then unify pre-check ordering and API-misuse classification through the shared verifier (B08).

### B33 — `VerifyWitnessProgram` positional callback broken
**`scripteval.py:559‑573`** · source **F‑23**. `0b881f7` ended the signature with `…, on_step`; `984705d` inserted `spent_outputs, execdata` before it. An old positional callback now binds to `spent_outputs`: v0 paths can silently collect no steps, while Taproot paths may fail when the callable is treated as a prevout sequence. **Fix:** first preserve/shim the historical callback position and emit a deprecation warning; only then make extension parameters keyword-only. Add signature-compatibility tests and document which APIs are public.

### B34 — `VerifySignature` can’t verify Taproot
**`scripteval.py:1994‑2023`** · source **F‑24**. It calls `VerifyScript` without `spent_outputs`, so it can’t verify taproot spends. **Fix:** accept/provide the full prevout sequence, or explicitly reject+document; add multi‑input tests.

### B35 — `OP_CHECKSIGADD` failure ordering vs Core
**`scripteval.py:1509‑1519`** · source **F‑25**. The fork checks empty/unknown‑pubkey **before** decrementing the sigops budget; Core’s shared tapscript checksig decrements first for every non‑empty signature. Both reject the same tx (no acceptance impact), but error/trace and budget accounting differ in edge cases. **Fix:** route CHECKSIG/CHECKSIGADD through one helper matching Core’s order.

### B36 — `TraceStep` typing has no real contract
**`scripteval.py:1223‑1256`** · source **F‑23**. `total=False` makes every field optional (so it didn’t catch B07); `hashtype_name` is emitted but undeclared (`type: ignore`); `kind` is unrestricted; the type isn’t exported. **Fix:** a required common base + `OpcodeTraceStep`/`ValidatorTraceStep` variants with `Literal` discriminators; export public types.

### B37 — rawBit filters all new SegWit validator steps
**rawBit `ScriptExecutionSteps.tsx:637‑641,676‑682`** · source **F‑26**. rawBit drops every `phase=="witness"` event from the interactive/copied trace, so commit `435e481`’s detailed BIP141/143 validator steps are generated but never walkable — conflicting with the library comment that the UI renders validator events distinctly. The backend still consumes events such as `scriptcode_derive` and `witness_script_check` to populate `scriptCode`/`witnessScript`, and the events remain in returned JSON. **Fix:** expose a collapsible “validator rules” phase or explicitly document the product choice and update comments. Do **not** remove generation unless the backend derivation and external trace contract are replaced.

### B38 — Metadata / provenance inaccurate
**`setup.py:31`, README, `plan.md`, `release-notes.md`, vector files** · source **F‑27**. `url` still points upstream; README badge/PyPI link are upstream; the summary omits Taproot/Tapscript; install text recommends mutable `master`; release notes still say `v1.1.5`; vectors lack a provenance manifest (source commit/date/license/hash). **Fix:** tag a signed fork release, update URLs/badges/changelog/support policy, add a checksum‑verified provenance manifest, and recommend the immutable commit/tag.

---

## 6. Not bugs / reclassified (adjudicated)

These were raised in Claude’s report; the cross‑review rejects or downgrades them. Recorded so they’re not re‑litigated.

- **M12 — SegWit‑v0 amount vs `spent_outputs` → *NOT a bug*.** BIP‑143 intentionally takes the current input’s amount via the existing `amount` parameter; BIP‑341 requires the full vin‑ordered `spent_outputs`. They are separate concepts. Auto‑deriving BIP‑143 amount from `spent_outputs` would be an API redesign, and since `amount=0` is a legitimate value and the current default, the function can’t even distinguish “omitted” from “explicitly zero” without changing to `Optional[int]`. **Do not change.**
- **M11 — `spent_outputs[inIdx]` consistency → *app‑side hardening, not a verifier defect*.** The verifier can’t independently discover the real UTXOs; `spent_outputs` is the caller’s asserted BIP‑341 context, and hashing bad caller data is expected. Downgrade to a rawBit diagnostics suggestion (cross‑check rawBit’s separately entered amount/scriptPubKey against `spent_outputs[inIdx]`), described as **application validation**, not a consensus defect.
- **M5 — data pushes named “unknown opcode” → *by design per the pinned integration contract*.** The integration spec required preserving `_opcode_name()` output and having rawBit normalize it to `PUSH n bytes` (which it does). Changing the library now would violate the pinned contract. The *genuine* naming omission is **B26** (`OP_CHECKSIGADD`).
- **H3 fourth cause — `spent_outputs` length ≠ `vin` → *caller API misuse*.** Raising a plain `ValueError` for a malformed argument is a reasonable Python idiom (upstream does the same, and `VerifyScript` already raises non‑`ValidationError` `TypeError` for bad script classes). Kept out of B04; optionally validate length up front for a friendlier message.

---

## 7. Confirmed correct (fixes & non‑issues) — do not "fix"

- **✅ Annex‑hash raw write is a correct fix of an upstream consensus bug.** Upstream length‑prefixed the 32‑byte annex hash (spurious `0x20`); the fork’s `f.write(annex_hash)` matches BIP‑341, and the caller computes `sha256(compact_size(len(annex)) || annex)` at `scripteval.py:727‑729`. *Add a unit test pinning the annex sighash bytes so a rebase can’t reintroduce the prefix.*
- **✅ `SIGHASH_SINGLE` `>` → `>=` bound (commit `387e9f6`) is a correct fix** of an upstream off‑by‑one; the only residual is the exception *type* (B04 cause 3).
- **✅ Corpus‑scale correctness.** All 2244 `script_assets` entries (3737 cases) match Core’s expected accept/reject; `VerifyScript` vs `VerifyScriptWithTrace` over 4945 cases = **0 acceptance divergences**. Encode this as a permanent CI parity test (the two functions are hand‑copied and have already drifted). *Caveat: the corpus always supplies prevouts and mostly valid flag combinations, so it cannot detect B09 or B08 — those needed the flag‑matrix/edge probing that surfaced them.*
- **✅ Vector authenticity.** `script_tests.json`, `script_assets_test.json`, BIP‑340 CSV, and `wallet-test-vectors.json` are byte‑identical to Bitcoin Core v30 / the BIPs. No vectors were doctored.
- **Enabled BIP‑65/112 (after `99eac23`), ordinary SegWit‑v0, BIP‑341 structural checks, and BIP‑342 execution semantics** were verified correct across both audits, except the specific findings above.

---

## 8. Consolidated fix roadmap

**Phase 1 — immediate release blockers, landed in parallel:**
1. **B01** — fix CODESEPARATOR with `sop_pc + 1` and add the exact accept/reject vectors. *(The only wrong-accept identified by this audit.)*
2. **B10** — repair Actions triggers, pin libsecp256k1 explicitly, and fail when the version is empty so the B01 regression test becomes a real gate.
3. **B21/B28** — remove validity-mismatch `xfail`, expand the four templates, stop comment dedup, and assert collection counts/checksums.
4. **B06** — add immediate rawBit request/trace caps and ensure timeout/resource exceptions escape the verifier wrapper.
5. **B07** — make the React viewer defensive against missing fields now; the versioned-schema cleanup can follow.
6. **B08/B32** — land the small `WITNESS ⇒ P2SH` and `CLEANSTACK ⇒ WITNESS` guards now rather than waiting for the shared-verifier refactor.

**Phase 2 — remaining consensus and primary-API correctness (focused commits, no trace redesign mixed in):**
1. **B02/B03** — unsigned CSV `nVersion` comparison and BIP143 unsigned `nLockTime` (`<I`).
2. **B04** — narrowly map the three genuine Taproot/tapscript invalid-input leaks without swallowing caller errors.
3. **B05** — implement the optional old/new secp256k1 negate binding and restore meaningful tests.
4. **B09** — remove the global signatureless-tapscript prevout gate; let actual sighash sites require context.
5. **B11** — run pubkey policy checks before the empty-signature return, without indexing an empty signature.

Run the full QA corpus after each commit; use no runtime `xfail` for any new validity divergence.

**Phase 3 — Core-v30 flag and policy parity:** B12 (P2A), B13 (native TAPROOT-off behavior), B14 (disabled CLTV/CSV), and B25 (full CONST_SCRIPTCODE or an explicit supported-subset label). Build a table-driven test over native/P2SH × witness version/length × feature flag × discourage flag vs Core, including all dependency checks from B08/B32.

**Phase 4 — one verifier, one versioned trace protocol:** refactor `VerifyScript`/`VerifyScriptWithTrace` onto one private implementation (B08); add explicit wrapper-boundary exception classification (B18/B32); introduce discriminated/versioned trace events (B07/B36); represent inactive-branch processing accurately (B15); provide exactly one terminal failure event unless truncated (B17); add annex/OP_SUCCESS/final-stack events (B19); and replace full repeated stack snapshots with bounded/delta recording (B06). Coordinate library + rawBit for pinned `step` names (B16), with rawBit accepting old and canonical aliases during migration.

**Phase 5 — release and artifact hardening:** fix the remaining range lint/mypy errors; test the supported Python/libsecp matrix (B05/B27); build, install, and smoke-test wheel+sdist (B24); add Taproot trace coverage (B22); add the full corpus and trace/non-trace parity tests from §7; and run the rawBit backend suite as a downstream CI job.

**Phase 6 — rawBit product integration:** expose all active flags plus consensus/policy presets (B23); remove the static multi-input prevout blockade and surface runtime context requirements (B09); render validator events defensively including old cached forms (B07/B16); expose or explicitly document the SegWit validator-rule phase without removing backend-consumed events (B37); show trace truncation and enforce per-request resource limits (B06); add cross-repo fixtures in which Python exports real JSON and TypeScript renders it.

**Lower-priority tail:** B26, B29, B30, B31, B33, B34, B35, B38.

**Release exit criteria for a “Bitcoin Core v30 compatible” claim:** B01–B14 resolved or explicitly scoped out in docs; B21/B28 converted into strict gates; zero validity mismatches on the full Core v30 + QA corpus; no dynamic `xfail` for validity divergence; trace and non-trace results identical across the flag matrix; every non-truncated failure has a structured terminal trace event; trace resource caps tested against adversarial maximum-request-size tapscript; Python/libsecp matrix green in public CI; artifacts install and smoke-test; rawBit backend + trace-UI integration green.

---

## 9. Cross‑reference map (source ID → unified ID)

| Claude | Codex | Unified |
|---|---|---|
| C1 | F‑01 | B01 |
| H1 | — | B02 |
| — | F‑03 | B03 |
| H3 (3 of 4 causes) | F‑22 | B04 |
| H4 | F‑09 | B05 |
| M1 | F‑08 | B06 |
| M7 | F‑07 | B07 |
| M9 | F‑06 | B08 |
| — | F‑02 | B09 |
| — | F‑04 | B10 |
| M2 | F‑10 | B11 |
| H2 | F‑12 | B12 |
| M3 | F‑11 | B13 |
| — | F‑13 | B14 |
| M4 | F‑15 | B15 |
| M6 | F‑17 | B16 |
| M8 | F‑16 | B17 |
| M10 | F‑17 | B18 |
| info | F‑17 | B19 |
| M13 | F‑21 | B20 |
| M14, M15 | F‑05, F‑21 | B21 |
| M16 | — | B22 |
| — | F‑18 | B23 |
| info | F‑20 | B24 |
| L1 | F‑14 | B25 |
| (missed) | F‑26 | B26 |
| L2 | F‑19 | B27 |
| L3 | F‑05 | B28 |
| L4 | F‑27 | B29 |
| L5 | — | B30 |
| L6 | — | B31 |
| L7, L8 | F‑25 | B32 |
| — | F‑23 | B33 |
| — | F‑24 | B34 |
| — | F‑25 | B35 |
| — | F‑23 | B36 |
| — | F‑26 | B37 |
| — | F‑27 | B38 |
| **M5** | — | *reclassified — by design (§6); real omission is B26* |
| **M11** | — | *reclassified — app hardening (§6)* |
| **M12** | — | *not a bug (§6)* |

*All line numbers reference the working tree at `435e481`. Behavioral findings were reproduced against that tree; B10/B23/B24/B33/B34/B37/B38 are static/downstream observations from the source and the rawBit `@ 880c30e` checkout.*
