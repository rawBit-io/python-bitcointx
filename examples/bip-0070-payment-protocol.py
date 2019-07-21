#!/usr/bin/env python3

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

"""Bip-0070-related functionality

Creates http response objects suitable for use with
bitcoin bip 70 using googles protocol buffers.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler

# generate paymentrequest_pb2 with protobuf compiler as described in
# https://developers.google.com/protocol-buffers/docs/pythontutorial
# using .proto file located at
# https://github.com/bitcoin/bips/blob/master/bip-0070/paymentrequest.proto
import paymentrequest_pb2 as o

# import bitcointx

from bitcointx.wallet import CCoinAddress
from bitcointx.core.script import CScript
from bitcointx.rpc import RPCCaller

from time import time

# bitcointx.select_chain_params('bitcoin/regtest')

listen_on = {'host': '127.0.0.1', 'port': 8080}
req_url_path = 'payment_request'
ack_url_path = 'payment_ack'


def payment_request():
    """Generates a http PaymentRequest object"""

    bc = RPCCaller(allow_default_conf=True)
    btc = CCoinAddress(bc.getnewaddress())

#   Setting the 'amount' field to 0 (zero) should prompt the user to enter
#   the amount for us but a bug in bitcoin core qt version 0.9.1 (at time of
#   writing) wrongly informs us that the value is too small and aborts.
#   https://github.com/bitcoin/bitcoin/issues/3095
#   Also there can be no leading 0's (zeros).
    btc_amount = 100000
    serialized_pubkey = btc.to_scriptPubKey()

    pdo = o.PaymentDetails(network="regtest")
    # pdo.network = 'test'
    pdo.outputs.add(amount=btc_amount, script=serialized_pubkey)
    pdo.time = int(time())
    pdo.memo = 'String shown to user before confirming payment'
    pdo.payment_url = 'http://{}:{}/{}'.format(listen_on['host'],
                                               listen_on['port'],
                                               ack_url_path)

    pro = o.PaymentRequest()
    pro.serialized_payment_details = pdo.SerializeToString()

    sds_pr = pro.SerializeToString()

    headers = {'Content-Type': 'application/bitcoin-payment',
               'Accept': 'application/bitcoin-paymentrequest'}

    return sds_pr, headers


def payment_ack(serialized_payment_message):
    """Generates a PaymentACK object, captures client refund address
    and returns a tuple (message, refund_address)"""

    pao = o.PaymentACK()
    pao.payment.ParseFromString(serialized_payment_message)
    pao.memo = 'String shown to user after payment confirmation'

    refund_address = CCoinAddress.from_scriptPubKey(
        CScript(pao.payment.refund_to[0].script))

    sds_pa = pao.SerializeToString()

    headers = {'Content-Type': 'application/bitcoin-payment',
               'Accept': 'application/bitcoin-paymentack'}

    return sds_pa, headers, refund_address


class ReqHandler(BaseHTTPRequestHandler):

    def _common_resp(self, data, headers):
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == '/' + req_url_path:
            data, headers = payment_request()
            self._common_resp(data, headers)
        else:
            self.send_error(404, 'wrong url')

    def do_POST(self):
        if self.path == '/' + ack_url_path:
            content_length = int(self.headers['Content-Length'])
            payment_message = self.rfile.read(content_length)
            data, headers, refund_address = payment_ack(payment_message)
            print("Client's refund address: ", str(refund_address))
            self._common_resp(data, headers)
        else:
            self.send_error(404, 'wrong url')


if __name__ == '__main__':
    httpd = HTTPServer((listen_on['host'], listen_on['port']), ReqHandler)
    httpd.serve_forever()
