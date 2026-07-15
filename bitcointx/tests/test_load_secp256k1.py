# Copyright (C) 2020 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest

import ctypes
import binascii
from typing import cast

import bitcointx.core.secp256k1 as secp256k1_module
from bitcointx.core.secp256k1 import (
    secp256k1_load_library, Secp256k1
)


class _FakeFunction:
    pass


class _FakeCDLL:
    _OLD_NEGATE = 'secp256k1_ec_privkey_negate'
    _NEW_NEGATE = 'secp256k1_ec_seckey_negate'

    def __init__(self, *, old_negate: bool, new_negate: bool) -> None:
        self._missing = set()
        if old_negate:
            setattr(self, self._OLD_NEGATE, _FakeFunction())
        else:
            self._missing.add(self._OLD_NEGATE)
        if new_negate:
            setattr(self, self._NEW_NEGATE, _FakeFunction())
        else:
            self._missing.add(self._NEW_NEGATE)

    def __getattr__(self, name: str) -> object:
        if name in self._missing:
            return None
        func = _FakeFunction()
        setattr(self, name, func)
        return func


class Test_Load_Secp256k1(unittest.TestCase):
    def test_privkey_negate_symbol_compatibility(self) -> None:
        cases = (
            ('old-only', True, False, True, 'old'),
            ('new-only', False, True, True, 'new'),
            ('both', True, True, True, 'old'),
            ('neither', False, False, False, None),
        )

        for name, has_old, has_new, expected_cap, preferred in cases:
            with self.subTest(name=name):
                lib = _FakeCDLL(old_negate=has_old, new_negate=has_new)
                old_func = getattr(lib, lib._OLD_NEGATE, None)
                new_func = getattr(lib, lib._NEW_NEGATE, None)

                # This deliberately duck-typed test double provides the CDLL
                # attributes used by _add_function_definitions.
                cap = secp256k1_module._add_function_definitions(
                    cast(ctypes.CDLL, lib))

                self.assertEqual(cap.has_privkey_negate, expected_cap)
                if preferred == 'old':
                    self.assertIs(getattr(lib, lib._OLD_NEGATE), old_func)
                elif preferred == 'new':
                    self.assertIs(getattr(lib, lib._OLD_NEGATE), new_func)
                else:
                    self.assertIsNone(getattr(lib, lib._OLD_NEGATE, None))

    def test(self) -> None:

        def check_pub_parse(secp256k1: Secp256k1) -> None:
            pub = binascii.unhexlify('037b6e1e0cb249ae1c8320543a8f1d3f43c093529d9e838c47616c9c9f587ad818')  # noqa
            raw_pub = ctypes.create_string_buffer(64)
            result = secp256k1.lib.secp256k1_ec_pubkey_parse(
                secp256k1.ctx.verify, raw_pub, pub, len(pub))
            assert result == 1

            result = secp256k1.lib.secp256k1_ec_pubkey_parse(
                secp256k1.ctx.verify, raw_pub, b'\xFF'*32, 32)
            assert result == 0

            k = binascii.unhexlify('309355fdb2cd1de2edc859012f451d5009147d0bf3a52cee02d2511cca483132') # noqa
            result = secp256k1.lib.secp256k1_ec_privkey_tweak_add(
                secp256k1.ctx.sign, k, b'\xAA'*32)
            assert result == 1

        # check with system-defined path search
        secp256k1_def = secp256k1_load_library()
        assert isinstance(secp256k1_def.lib, ctypes.CDLL)
        check_pub_parse(secp256k1_def)

        # check with explicit path
        path = ctypes.util.find_library('secp256k1')
        secp256k1_ep = secp256k1_load_library(path=path)
        assert isinstance(secp256k1_ep.lib, ctypes.CDLL)
        check_pub_parse(secp256k1_ep)
