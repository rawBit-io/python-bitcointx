#!/usr/bin/env python3
#
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

from bitcointx import select_chain_params
from bitcointx.wallet import CCoinKey, P2PKHCoinAddress
from bitcointx.signmessage import BitcoinMessage, VerifyMessage, SignMessage


def sign_message(key, msg):
    secret = CCoinKey(key)
    message = BitcoinMessage(msg)
    return SignMessage(secret, message)


def print_default(signature, key=None, msg=None):
    print(signature.decode('ascii'))


def print_verbose(signature, key, msg):
    secret = CCoinKey(key)
    address = P2PKHCoinAddress.from_pubkey(secret.pub)
    message = BitcoinMessage(msg)
    print('Address: %s' % address)
    print('Message: %s' % msg)
    print('Signature: %s' % signature)
    print('Verified: %s' % VerifyMessage(address, message, signature))
    print('\nTo verify using bitcoin core:')
    print('\n`bitcoin-cli verifymessage %s \'%s\' \'%s\'`\n'
          % (address, signature.decode('ascii'), msg))


def parser():
    import argparse
    parser = argparse.ArgumentParser(
        description='Sign a message with a private key.',
        epilog=('Security warning: arguments may be visible to other users '
                'on the same host.'))
    parser.add_argument(
        '-v', '--verbose', dest='print_result',
        action='store_const', const=print_verbose, default=print_default,
        help='verbose output')
    parser.add_argument(
        '-k', '--key',
        required=True,
        help='private key in base58 encoding')
    parser.add_argument(
        '-m', '--msg',
        required=True,
        help='message to sign')
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
    try:
        signature = sign_message(args.key, args.msg)
    except Exception as error:
        print('%s: %s' % (error.__class__.__name__, str(error)))
        exit(1)
    else:
        args.print_result(signature, args.key, args.msg)
