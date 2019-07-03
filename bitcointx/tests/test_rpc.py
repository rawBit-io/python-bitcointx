# Copyright (C) 2013-2014 The python-bitcoinlib developers
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

import unittest

from bitcointx.rpc import RPCCaller


class Test_RPC(unittest.TestCase):
    # Tests disabled, see discussion below.
    # "Looks like your unit tests won't work if Bitcoin Core isn't running;
    # maybe they in turn need to check that and disable the test
    # if core isn't available?"
    # https://github.com/petertodd/python-bitcoinlib/pull/10

    # NOTE: if we add MockRPCCaller to create mocked RPC interface,
    # then maybe we can add tests that will make sense.
    # For now, just test that we can create the instance.
    RPCCaller(service_url='http://user:pass@host')

#    def test_can_validate(self):
#        working_address = '1CB2fxLGAZEzgaY4pjr4ndeDWJiz3D3AT7'
#        p = Proxy()
#        r = p.validateAddress(working_address)
#        self.assertEqual(r['address'], working_address)
#        self.assertEqual(r['isvalid'], True)
#
#    def test_cannot_validate(self):
#        non_working_address = 'LTatMHrYyHcxhxrY27AqFN53bT4TauR86h'
#        p = Proxy()
#        r = p.validateAddress(non_working_address)
#        self.assertEqual(r['isvalid'], False)
