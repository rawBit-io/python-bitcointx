import json
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from bitcointx.core import CoreCoinParams, b2x, x
from bitcointx.core.key import XOnlyPubKey, compute_tap_tweak_hash
from bitcointx.core.script import (
    CScript,
    TaprootScriptTree,
    TaprootScriptTreeLeaf_Type,
)
from bitcointx.core.serialize import VarIntSerializer
from bitcointx.wallet import P2TRCoinAddress


def _encode_varint(n: int) -> bytes:
    buf = BytesIO()
    VarIntSerializer.stream_serialize(n, buf)
    return buf.getvalue()


def _tapleaf_hash(script_hex: str, leaf_version: int) -> bytes:
    script = x(script_hex)
    return CoreCoinParams.tapleaf_hasher(
        bytes([leaf_version]) + _encode_varint(len(script)) + script
    )


def _build_tree(
    stree_data: Any, internal_pubkey: XOnlyPubKey
) -> Tuple[TaprootScriptTree, Dict[str, CScript], List[bytes]]:
    scripts: Dict[str, CScript] = {}
    leaf_hashes: List[bytes] = []

    def process_leaves(leaves_data: List[Any]) -> List[TaprootScriptTreeLeaf_Type]:
        leaves: List[TaprootScriptTreeLeaf_Type] = []
        for ld in leaves_data:
            if isinstance(ld, dict):
                name = f"id_{ld['id']}"
                script_hex = ld["script"]
                cs = CScript(x(script_hex), name=name)
                scripts[name] = cs
                leaf_version = ld["leafVersion"]
                leaf_hashes.append(_tapleaf_hash(script_hex, leaf_version))
                leaf: TaprootScriptTreeLeaf_Type = cs
                if leaf_version != CoreCoinParams.TAPROOT_LEAF_TAPSCRIPT:
                    leaf = TaprootScriptTree([cs], leaf_version=leaf_version)
                leaves.append(leaf)
            else:
                # Nested list becomes an unbalanced subtree
                leaves.append(TaprootScriptTree(process_leaves(ld)))
        return leaves

    leaves_arg = stree_data if isinstance(stree_data, list) else [stree_data]
    tree = TaprootScriptTree(process_leaves(leaves_arg), internal_pubkey=internal_pubkey)
    return tree, scripts, leaf_hashes


def _load_scriptpubkey_cases() -> List[Dict[str, Any]]:
    path = Path(__file__).with_name("data") / "wallet-test-vectors.json"
    data = json.loads(path.read_text())
    assert data["version"] == 1
    return data["scriptPubKey"]


_SCRIPT_PUBKEY_CASES = _load_scriptpubkey_cases()


@pytest.mark.parametrize(
    "tcase", _SCRIPT_PUBKEY_CASES, ids=lambda c: c["given"]["internalPubkey"]
)
def test_bip341_script_pubkey_vectors(tcase: Dict[str, Any]) -> None:
    given = tcase["given"]
    intermediary = tcase["intermediary"]
    expected = tcase["expected"]

    int_pub = XOnlyPubKey(x(given["internalPubkey"]))
    stree_data = given["scriptTree"]

    scripts: Dict[str, CScript]
    if stree_data is None:
        merkle_root = b""
        leaf_hashes: List[bytes] = []
        stree = None
        adr = P2TRCoinAddress.from_pubkey(int_pub)
    else:
        stree, scripts, leaf_hashes = _build_tree(stree_data, int_pub)
        merkle_root = stree.merkle_root
        adr = P2TRCoinAddress.from_script_tree(stree)

    expected_leaf_hashes = intermediary.get("leafHashes")
    if expected_leaf_hashes is not None:
        assert [lh.hex() for lh in leaf_hashes] == expected_leaf_hashes

    if intermediary.get("merkleRoot") is not None:
        assert b2x(merkle_root) == intermediary["merkleRoot"]

    tweak = compute_tap_tweak_hash(int_pub, merkle_root=merkle_root)
    assert tweak.hex() == intermediary["tweak"]
    assert adr.hex() == intermediary["tweakedPubkey"]

    spk = adr.to_scriptPubKey()
    assert b2x(spk) == expected["scriptPubKey"]
    assert str(adr) == expected["bip350Address"]

    for idx, expected_cb in enumerate(expected.get("scriptPathControlBlocks", [])):
        assert stree is not None
        sname = f"id_{idx}"
        script_with_cb = stree.get_script_with_control_block(sname)
        assert script_with_cb is not None
        script, cb = script_with_cb
        assert script == scripts[sname]
        assert b2x(cb) == expected_cb
