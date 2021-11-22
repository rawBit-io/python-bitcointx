#!/usr/bin/env python3
#
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

import sys
import argparse
from typing import Optional, Union

from bitcointx import select_chain_params
from bitcointx.core import b2x
from bitcointx.core.key import KeyStore, BIP32PathTemplate
from bitcointx.core.psbt import PartiallySignedTransaction
from bitcointx.base58 import Base58Error
from bitcointx.wallet import CCoinKey, CCoinExtKey


def parser() -> 'argparse.ArgumentParser':
    parser = argparse.ArgumentParser(
        description='Sign PSBT with specified keys.',
        epilog=('Security warning: arguments may be visible to other users '
                'on the same host.'))
    parser.add_argument(
        '-k', '--key', nargs='*',
        help='List of private keys or extended private keys (base58 encoding)')
    parser.add_argument('--path-template',
                        help='Path template for signing checks')
    parser.add_argument('--without-path-template-checks',
                        dest='without_path_template_checks',
                        action='store_true',
                        help='Sign without path template checks')
    parser.add_argument('-f', '--finalize', action='store_true',
                        help='Finalize transaction')
    parser.add_argument(
        '-i', '--input-file',
        required=True,
        help='file with psbt (can be \'-\' for stdin)')
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

    if args.input_file == '-':
        psbt_data = sys.stdin.read()
    else:
        with open(args.input_file, 'r') as f:
            psbt_data = f.read()

    path_template = None
    require_path_templates = True
    if args.path_template is not None:
        if args.without_path_template_checks:
            print('--without-path-template-checks conflicts with '
                  '--path-template argument')
            sys.exit(-1)
        path_template = BIP32PathTemplate(args.path_template)
    elif args.without_path_template_checks:
        require_path_templates = False

    keys = []
    for key_index, key_data in enumerate(args.key or []):
        k: Optional[Union[CCoinKey, CCoinExtKey]] = None
        try:
            k = CCoinKey(key_data)
        except (ValueError, Base58Error):
            pass

        try:
            k = CCoinExtKey(key_data)
        except (ValueError, Base58Error):
            pass

        if k is None:
            print(f'key at position {key_index} is not in recognized format')
            sys.exit(-1)
        keys.append(k)

    psbt = PartiallySignedTransaction.from_base64_or_binary(psbt_data)
    sign_result = psbt.sign(
        KeyStore.from_iterable(keys,
                               default_path_template=path_template,
                               require_path_templates=require_path_templates),
        finalize=args.finalize)

    print("")
    print(f'Transaction has total {len(psbt.inputs)} inputs\n')
    print(f'Added signatures to {sign_result.num_inputs_signed} inputs')
    print(f'{sign_result.num_inputs_final} inputs is finalized')
    if not sign_result.is_final:
        print(f'{sign_result.num_inputs_ready} inputs is ready '
              f'to be finalized\n')
    else:
        assert sign_result.num_inputs_ready == 0

    if not sign_result.is_final and sign_result.num_inputs_signed > 0:
        for index, info in enumerate(sign_result.inputs_info):
            if info:
                print(f"Input {index}: added {info.num_new_sigs} sigs, ",
                      end='')
                print("input is now final"
                      if info.is_final
                      else f"{info.num_sigs_missing} is still missing")
            else:
                print(f"Input {index}: skipped, cannot be processed")

    print()
    if args.finalize:
        if not sign_result.is_final:
            print('Failed to finalize transaction')
            sys.exit(-1)

        print("Signed network transaction:\n")
        print(b2x(psbt.extract_transaction().serialize()))
    elif sign_result.num_inputs_signed == 0:
        print("Could not sign any inputs")
        sys.exit(-1)
    else:
        print("PSBT with added signatures:\n")
        print(psbt.to_base64())
