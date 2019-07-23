#!/usr/bin/env python3

# Copyright (C) 2014 The python-bitcoinlib developers
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

"""Example of timestamping a file via OP_RETURN"""

import sys

import bitcointx.rpc

from bitcointx import select_chain_params
from bitcointx.core import (
    Hash, x, lx, b2x, coins_to_satoshi, CoreCoinParams,
    CTransaction, CTxIn, CMutableTxOut, COutPoint
)
from bitcointx.core.script import CScript, OP_RETURN, OP_CHECKSIG

if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)


def parser():
    import argparse

    parser = argparse.ArgumentParser(
        description=('publish transaction with OP_RETURN containing a hash '
                     'of file'))
    parser.add_argument(
        '-f', '--hash-file', required=True, action='append',
        help='file to hash its contents and use hash in OP_RETURN')
    parser.add_argument('-t', '--testnet', action='store_true',
                        dest='testnet', help='Use testnet')
    parser.add_argument('-r', '--regtest', action='store_true',
                        dest='regtest', help='Use regtest')
    return parser


if __name__ == '__main__':
    args = parser().parse_args()
    if args.testnet:
        select_chain_params('bitcoin/testnet')
    elif args.regtest:
        select_chain_params('bitcoin/regtest')

    rpc = bitcointx.rpc.RPCCaller(allow_default_conf=True)

    digests = []
    for f in args.hash_file:
        try:
            with open(f, 'rb') as fd:
                digests.append(Hash(fd.read()))
        except FileNotFoundError as exp:
            if len(f)/2 in (20, 32):
                digests.append(x(f))
            else:
                raise exp
        except IOError as exp:
            print(exp, file=sys.stderr)
            continue

    for digest in digests:
        txouts = []

        unspent = sorted(rpc.listunspent(0), key=lambda x: hash(x['amount']))

        txins = [CTxIn(COutPoint(lx(unspent[-1]['txid']),
                                 int(unspent[-1]['vout'])))]
        value_in = coins_to_satoshi(unspent[-1]['amount'])

        change_addr = rpc.getnewaddress()
        change_pubkey_hex = rpc.getaddressinfo(change_addr)['pubkey']
        change_out = CMutableTxOut(CoreCoinParams.MAX_MONEY,
                                   CScript([x(change_pubkey_hex),
                                            OP_CHECKSIG]))

        digest_outs = [CMutableTxOut(0, CScript([OP_RETURN, digest]))]

        txouts = [change_out] + digest_outs

        tx = CTransaction(txins, txouts).to_mutable()

        FEE_PER_VBYTE = 0.00025*CoreCoinParams.COIN/1000
        while True:
            required_fee = tx.get_virtual_size() * FEE_PER_VBYTE
            tx.vout[0].nValue = int(
                value_in - max(required_fee, 0.00011*CoreCoinParams.COIN))

            r = rpc.signrawtransactionwithwallet(b2x(tx.serialize()))
            assert r['complete']
            tx = CTransaction.deserialize(x(r['hex']))

            if value_in - tx.vout[0].nValue >= required_fee:
                tx_bytes = tx.serialize()
                tx_hex = b2x(tx_bytes)
                print(tx_hex)
                print(len(tx_bytes), 'bytes', file=sys.stderr)
                print(rpc.sendrawtransaction(tx_hex))
                break
