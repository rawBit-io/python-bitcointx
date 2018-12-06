# Copyright (C) 2013-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcointx.core.key import *
from bitcointx.core import x

class Test_CPubKey(unittest.TestCase):
    def test(self):
        def T(hex_pubkey, is_valid, is_fullyvalid, is_compressed):
            key = CPubKey(x(hex_pubkey))
            self.assertEqual(key.is_valid, is_valid)
            self.assertEqual(key.is_fullyvalid, is_fullyvalid)
            self.assertEqual(key.is_compressed, is_compressed)

        T('', False, False, False)
        T('00', True, False, False) # Note: deemed valid by OpenSSL for some reason
        T('01', True, False, False)
        T('02', True, False, False)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)
        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, False, True)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)

        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          True, True, False)

class Test_CKey(unittest.TestCase):
    def test(self):
        def T(keydata, compressed, uncompressed):
            k = CKey(x(keydata))
            assert k.is_compressed
            assert k.pub == x(compressed)
            k.set_compressed(False)
            assert not k.is_compressed
            assert k.pub == x(uncompressed)

        T('0de5306487851213f0aae1454f4e4449949a755802b60f6eb47906149395d080',
          '023bd76d581c4823f66d8f3f6462dfdb3c8823ba77c7e8b5284d04b41b83659811',
          '043bd76d581c4823f66d8f3f6462dfdb3c8823ba77c7e8b5284d04b41b836598111af4e26a83ff8e3e0eef15eca09953f9a3d3c2c15807c5ef68a180fb8d4260c6')
        T('c9ff05edfbfb4710267ccf212fbb0414284b09fce621f8ab61a5b1cf0f3a5bf2',
          '029925633a4ba7d5f6f60d94213f65dfc482aa9b0f3cadb1ce20d7b7d792428209',
          '049925633a4ba7d5f6f60d94213f65dfc482aa9b0f3cadb1ce20d7b7d792428209973a2e2e14e13d6263c894fefd5374d1d2b0e637b2215209b55604c0bb4f1196')

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            CKey(b'\x00'*32)

        with self.assertRaises(ValueError):
            CKey(b'\xff'*32)
