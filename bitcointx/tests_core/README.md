# Tests in this directory

- **Script vectors**: `test_script_vectors.py` checks `VerifyScript` against Bitcoin Core’s `script_tests.json` (v30; legacy, P2SH, SegWit v0). Taproot template cases are `xfail` because placeholders like `#SCRIPT#`/`#CONTROLBLOCK#` are not expanded. Data lives in `data/script_tests.json`. Run with `pytest bitcointx/tests_core/test_script_vectors.py -vv`. Update vectors from a Core checkout via `cp src/test/data/script_tests.json bitcointx/tests_core/data/`.

- **BIP340 Schnorr primitives (phase 1)**: `test_bip340_schnorr.py` verifies BIP-0340 reference vectors from `data/test-vectors.csv` (valid/invalid Schnorr signatures, odd `R`, `s = n`, non-curve pubkeys, and variable-length messages). Verification uses libsecp256k1’s Schnorr support; the suite skips if the library was built without `schnorrsig`. Run with `pytest bitcointx/tests_core/test_bip340_schnorr.py -vv`.

- **BIP341 construction (phase 2)**: `test_bip341_construction.py` checks wallet/address construction against `data/wallet-test-vectors.json` (tweaks, tapleaf hashes, merkle root, control blocks, scriptPubKey, Bech32m addresses). Run with `pytest bitcointx/tests_core/test_bip341_construction.py -vv`.

- **BIP341 key-path + sighash (phase 3)**: `test_taproot_keypath.py` exercises key-path spends, SIGHASH modes (DEFAULT/ALL/NONE/SINGLE with/without ANYONECANPAY), invalid hashtypes/lengths, annex handling, and multi-input independence. Run with `pytest bitcointx/tests_core/test_taproot_keypath.py -vv`.

- **BIP341 script-path tapscript (phase 4)**: `test_taproot_scriptpath.py` filters relevant tapscript/script-path cases from `data/script_assets_test.json` (OP_SUCCESS, unknown leaf versions, MINIMALIF, cleanstack, control blocks, etc.) and checks both success and expected-fail variants. Run with `pytest bitcointx/tests_core/test_taproot_scriptpath.py -vv`.

- **BIP342 validation weight budget (phase 5)**: `test_tapscript_budget.py` runs the `tapscript/sigopsratio_*` cases from `data/script_assets_test.json` to exercise tapscript sigops/validation weight limits. Run with `pytest bitcointx/tests_core/test_tapscript_budget.py -vv`.

General suite (bitcointx/tests): the main repository tests (wallet, PSBT, scripteval, serialize, etc.) live in `bitcointx/tests`. Run them alone with `python -m pytest bitcointx/tests -vv` (or `python3 -m pytest ...`).

Run the full suite (general + tests_core) via `./bitcointx/tests_core/run_all.sh`.
