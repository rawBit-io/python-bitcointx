#!/usr/bin/env python3
#
# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from bitcointx import SelectAlternativeParams
from bitcointx.core import CBlock, x, COIN, CoreChainParams
from bitcointx.wallet import CBitcoinAddress


class CoreLitecoinParams(CoreChainParams):
    NAME = 'litecoin-mainnet'
    GENESIS_BLOCK = CBlock.deserialize(x(
        '0100000000000000000000000000000000000000000000000000000000000000'
        '00000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6'
        'bafbdd97b9aa8e4ef0ff0f1ecd513f7c01010000000100000000000000000000'
        '00000000000000000000000000000000000000000000ffffffff4804ffff001d'
        '0104404e592054696d65732030352f4f63742f32303131205374657665204a6f'
        '62732c204170706c65e280997320566973696f6e6172792c2044696573206174'
        '203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3'
        'a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f47'
        '0216fe1b51850b4acf21b179c45070ac7b03a9ac00000000'))
    SUBSIDY_HALVING_INTERVAL = 840000
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 20
    MAX_MONEY = 84000000 * COIN


class MainLitecoinParams(CoreLitecoinParams):
    RPC_PORT = 9332
    BASE58_PREFIXES = {'PUBKEY_ADDR': 48,
                       'SCRIPT_ADDR': 50,
                       'SECRET_KEY': 176,
                       'EXTENDED_PUBKEY': b'\x04\x88\xB2\x1E',
                       'EXTENDED_PRIVKEY': b'\x04\x88\xAD\xE4'}
    BECH32_HRP = 'ltc'
    BASE58_PREFIX_ALIAS = {5: 50}


if __name__ == '__main__':

    SelectAlternativeParams(CoreLitecoinParams, MainLitecoinParams)

    canonical_adr = 'MMDkQMv8pGGmAXdVyxaW8YtQMCHw7eouma'
    legacy_adr = '3F1c6UWAs9RLN2Mbt5bAJue12VhVCorXzs'

    adr = CBitcoinAddress(legacy_adr)

    assert str(adr) == canonical_adr

    print("")
    print("Litecoin address", legacy_adr)
    print("is an alias to  ", adr)
    print("but with P2SH script prefix 5 - the same as used by bitcoin.")
    print("Litecoin still supports this 'legacy' encoding after")
    print("introducing their native script prefix")
    print("")
