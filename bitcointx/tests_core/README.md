# Tests in this directory

- **Script vectors**: `test_script_vectors.py` checks `VerifyScript` against Bitcoin Core’s `script_tests.json` (v30; legacy, P2SH, SegWit v0). Taproot template cases are `xfail` because placeholders like `#SCRIPT#`/`#CONTROLBLOCK#` are not expanded. Data lives in `data/script_tests.json`. Run with `pytest bitcointx/tests_core/test_script_vectors.py -vv --capture=tee-sys 2>&1 | tee bitcointx/tests_core/results/script_vector_results.txt`. Update vectors from a Core checkout via `cp src/test/data/script_tests.json bitcointx/tests_core/data/`.

- **BIP340 Schnorr primitives (phase 1)**: `test_bip340_schnorr.py` verifies BIP-0340 reference vectors from `data/test-vectors.csv` (valid/invalid Schnorr signatures, odd `R`, `s = n`, non-curve pubkeys, and variable-length messages). Verification uses libsecp256k1’s Schnorr support; the suite skips if the library was built without `schnorrsig`. Run with `pytest bitcointx/tests_core/test_bip340_schnorr.py -vv`.

Each run writes a terse summary into `results/last_run.txt` (also kept as `results/script_vector_results.txt` for compatibility).
