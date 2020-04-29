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

import os
import ctypes
from bitcointx.core.secp256k1 import (
    load_secp256k1_library, SECP256K1_CONTEXT_SIGN
)


class Test_Load_Secp256k1(unittest.TestCase):
    def test(self) -> None:

        # check with system-defined path search
        handle = load_secp256k1_library()
        assert isinstance(handle, ctypes.CDLL)

        # check that it works
        ctx = handle.secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
        assert ctx is not None
        res = handle.secp256k1_context_randomize(ctx, os.urandom(32))
        assert res == 1

        # check with explicit path
        path = ctypes.util.find_library('secp256k1')
        handle = load_secp256k1_library(path=path)
        assert isinstance(handle, ctypes.CDLL)

        # check that it works
        ctx = handle.secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
        assert ctx is not None
        res = handle.secp256k1_context_randomize(ctx, os.urandom(32))
        assert res == 1
