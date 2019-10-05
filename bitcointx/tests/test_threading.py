# Copyright (C) 2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501

import unittest
import threading
import ctypes

from bitcointx import (
    select_chain_params, get_current_chain_params, BitcoinMainnetParams
)
from bitcointx.core import x, Hash160, CTransaction
from bitcointx.core.key import CPubKey
from bitcointx.core.script import CScript
from bitcointx.core.secp256k1 import (
    _secp256k1, secp256k1_get_last_error, secp256k1_context_verify
)
from bitcointx.wallet import (
    P2PKHCoinAddress, P2SHCoinAddress, P2WPKHCoinAddress
)
import bitcointx.bech32
from bitcointx.base58 import CBase58Data


class Test_Threading(unittest.TestCase):

    def test_addresses(self):
        pub = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))

        events = {
            'mainnet': threading.Event(),
            'testnet': threading.Event(),
            'regtest': threading.Event(),
        }

        # list append is thread-safe, can use just the list.
        finished_successfully = []

        def wait(name):
            not_timed_out = events[name].wait(timeout=5.0)
            assert not_timed_out

        def ready(name):
            events[name].set()

        def finish(name):
            finished_successfully.append(name)

        def check_core_modules():
            # check that mutable/immutable thread-local context works
            CTransaction().to_mutable().to_immutable()

            # check secp256k1 error handling (which uses thread-local storage)
            _secp256k1.secp256k1_ec_pubkey_tweak_add(
                secp256k1_context_verify,
                ctypes.c_char_p(0), ctypes.c_char_p(0))
            err = secp256k1_get_last_error()
            assert err['code'] == -2
            assert err['type'] == 'illegal_argument'
            assert 'message' in err

        def mainnet():
            select_chain_params('bitcoin/mainnet')
            wait('testnet')
            a = P2PKHCoinAddress.from_pubkey(pub)
            assert CBase58Data(str(a))[0] == 0
            check_core_modules()
            ready('mainnet')
            finish('mainnet')

        def testnet():
            select_chain_params('bitcoin/testnet')
            wait('regtest')
            a = P2SHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub) + b'\x87'))
            assert CBase58Data(str(a))[0] == 196
            check_core_modules()
            ready('testnet')
            wait('mainnet')
            finish('testnet')

        def regtest():
            select_chain_params('bitcoin/regtest')
            a = P2WPKHCoinAddress.from_pubkey(pub)
            witver, data = bitcointx.bech32.decode(
                P2WPKHCoinAddress.bech32_hrp, str(a))
            assert witver == 0
            assert data == Hash160(pub)
            check_core_modules()
            ready('regtest')
            wait('testnet')
            wait('mainnet')
            finish('regtest')

        assert isinstance(get_current_chain_params(), BitcoinMainnetParams), \
            "tests assume bitcoin params in effect by default"

        mainnet_thread = threading.Thread(target=mainnet)
        testnet_thread = threading.Thread(target=testnet)
        regtest_thread = threading.Thread(target=regtest)
        mainnet_thread.start()
        testnet_thread.start()
        regtest_thread.start()
        mainnet_thread.join()
        testnet_thread.join()
        regtest_thread.join()

        self.assertEqual(set(finished_successfully),
                         set(['mainnet', 'testnet', 'regtest']))
        self.assertIsInstance(get_current_chain_params(),
                              BitcoinMainnetParams)
