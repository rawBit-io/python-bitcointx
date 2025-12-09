# Bitcoin Core script vectors

- **Purpose**: Check `VerifyScript` against Bitcoin Core’s `script_tests.json` from Core v30 (legacy, P2SH, SegWit v0; Taproot template cases are `xfail` because placeholders like `#SCRIPT#`/`#CONTROLBLOCK#` are not expanded). The suite currently covers ~1.2k vectors.
- **What it exercises**: Signature rules (DER, low-S, sighash types), stack limits and conditional flow, timelocks (CLTV/CSV), witness program validation, push-only/scriptSig rules, discouraged/disabled opcodes, and CLEANSTACK/NULLDUMMY/NULLFAIL/MINIMALDATA behaviors.
- **How it works**: `test_script_vectors.py` parses ASM tokens into `CScript`, builds a minimal credit/spend tx pair, runs `VerifyScript`, and uses `_classify_exception` plus `_expected_matches` to align bitcointx errors with Core’s expected labels (including a few equivalence tweaks like CLEANSTACK ↔ EVAL_FALSE).
- **Files**: `script_tests.json` (Bitcoin Core v30 vectors), `test_script_vectors.py` (pytest harness), `script_vector_results.txt` (last run log).
- **Run**: `pytest bitcointx/tests_core/test_script_vectors.py -vv --capture=tee-sys 2>&1 | tee bitcointx/tests_core/script_vector_results.txt`
- **Update vectors**: Refresh from Bitcoin Core with `cp src/test/data/script_tests.json bitcointx/tests_core/` (from a Core checkout).
