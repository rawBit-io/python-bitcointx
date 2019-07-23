# Copyright (C) 2013-2015 The python-bitcoinlib developers
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

# pylama:ignore=E501,E201

import unittest

from bitcointx import BitcoinMainnetParams, ChainParams
from bitcointx.core import (
    str_money_value, MoneyRange, coins_to_satoshi, satoshi_to_coins,
    CoreBitcoinParams, CoreBitcoinClassDispatcher, CoreBitcoinClass,
)
from bitcointx.wallet import WalletBitcoinClassDispatcher
from bitcointx.util import classgetter


class Test_str_value(unittest.TestCase):
    def test(self):
        def T(value, expected):
            actual = str_money_value(value)
            self.assertEqual(actual, expected)

        T(         0,  '0.0')
        T(         1,  '0.00000001')
        T(        10,  '0.0000001')
        T(  12345678,  '0.12345678')
        T(  10000000,  '0.1')
        T( 100000000,  '1.0')
        T(1000000000, '10.0')
        T(1010000000, '10.1')
        T(1001000000, '10.01')
        T(1012345678, '10.12345678')


class Test_Money(unittest.TestCase):
    def test_MoneyRange(self):
        self.assertFalse(MoneyRange(-1))
        with self.assertRaises(ValueError):
            coins_to_satoshi(-1)
        with self.assertRaises(ValueError):
            satoshi_to_coins(-1)
        self.assertTrue(MoneyRange(0))
        self.assertTrue(MoneyRange(100000))
        max_satoshi = coins_to_satoshi(21000000)
        self.assertTrue(MoneyRange(max_satoshi))  # Maximum money on Bitcoin network
        self.assertFalse(MoneyRange(max_satoshi+1))
        with self.assertRaises(ValueError):
            coins_to_satoshi(max_satoshi+1)
        with self.assertRaises(ValueError):
            satoshi_to_coins(max_satoshi+1)

    def test_MoneyRangeCustomParams(self):

        class CoreHighMaxClassDispatcher(CoreBitcoinClassDispatcher):
            ...

        class CoreHighMaxParams(CoreBitcoinParams, CoreBitcoinClass):
            @classgetter
            def MAX_MONEY(self):
                return 22000000 * self.COIN

        class WalletHighMaxClassDispatcher(WalletBitcoinClassDispatcher):
            ...

        class HighMaxParams(BitcoinMainnetParams):
            NAME = 'high_maxmoney'
            WALLET_DISPATCHER = WalletHighMaxClassDispatcher

        with ChainParams(HighMaxParams):
            self.assertFalse(MoneyRange(-1))
            with self.assertRaises(ValueError):
                coins_to_satoshi(-1)
            with self.assertRaises(ValueError):
                satoshi_to_coins(-1)
            self.assertTrue(MoneyRange(0))
            self.assertTrue(MoneyRange(100000))
            max_satoshi = coins_to_satoshi(22000000)
            self.assertTrue(MoneyRange(max_satoshi))  # Maximum money on Bitcoin network
            self.assertFalse(MoneyRange(max_satoshi+1))
            with self.assertRaises(ValueError):
                coins_to_satoshi(max_satoshi+1)
            with self.assertRaises(ValueError):
                satoshi_to_coins(max_satoshi+1)
