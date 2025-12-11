import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import pytest

from bitcointx.core import x
from bitcointx.core.key import CKey, XOnlyPubKey
from bitcointx.core.secp256k1 import get_secp256k1


@dataclass(frozen=True)
class BIP340Vector:
    idx: int
    secret_key_hex: str
    pubkey: XOnlyPubKey
    aux_rand: Optional[bytes]
    message: bytes
    signature: bytes
    expected: bool
    comment: str


def _require_schnorr_support():
    secp = get_secp256k1()
    if not secp.cap.has_schnorrsig:
        pytest.skip("libsecp256k1 built without schnorrsig support")
    return secp


def _load_vectors() -> List[BIP340Vector]:
    path = Path(__file__).with_name("data") / "test-vectors.csv"
    with path.open(newline="") as fd:
        reader = csv.DictReader(fd)
        vectors: List[BIP340Vector] = []
        for row in reader:
            message = bytes.fromhex(row["message"]) if row["message"] else b""
            vectors.append(
                BIP340Vector(
                    idx=int(row["index"]),
                    secret_key_hex=row["secret key"],
                    pubkey=XOnlyPubKey(x(row["public key"])),
                    aux_rand=x(row["aux_rand"]) if row["aux_rand"] else None,
                    message=message,
                    signature=x(row["signature"]),
                    expected=row["verification result"].upper() == "TRUE",
                    comment=row["comment"],
                )
            )
    return vectors


_VECTORS = _load_vectors()
_SIGNABLE_VECTORS = [
    v for v in _VECTORS if v.secret_key_hex and len(v.message) == 32
]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: f"{v.idx}")
def test_bip340_vectors_verify(vector: BIP340Vector) -> None:
    secp = _require_schnorr_support()
    if not vector.pubkey.is_fullyvalid():
        assert vector.expected is False
        return

    pubkey_buf = vector.pubkey._to_ctypes_char_array()
    result = secp.lib.secp256k1_schnorrsig_verify(
        secp.ctx.verify,
        vector.signature,
        vector.message,
        len(vector.message),
        pubkey_buf,
    )
    assert bool(result) is vector.expected, f"vector {vector.idx}: {vector.comment}"


@pytest.mark.parametrize("vector", _SIGNABLE_VECTORS, ids=lambda v: f"{v.idx}")
def test_bip340_vectors_sign(vector: BIP340Vector) -> None:
    _require_schnorr_support()

    seckey = CKey(x(vector.secret_key_hex))
    signature = seckey.sign_schnorr_no_tweak(vector.message, aux=vector.aux_rand)
    assert signature == vector.signature
    assert vector.pubkey.verify_schnorr(vector.message, signature)
