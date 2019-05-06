# Copyright (C) 2012-2018 The python-bitcoinlib developers
# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from contextlib import contextmanager

import bitcointx.core
import bitcointx.core.script
import bitcointx.sidechain
import bitcointx.wallet

# Note that setup.py can break if __init__.py imports any external
# dependencies, as these might not be installed when setup.py runs. In this
# case __version__ could be moved to a separate version.py and imported here.
__version__ = '0.11.0.dev0'


class _ParamsTag():
    pass


class MainParams(bitcointx.core.CoreMainParams, _ParamsTag):
    RPC_PORT = 8332
    ADDRESS_CLASS = bitcointx.wallet.CBitcoinAddress
    KEY_CLASS = bitcointx.wallet.CBitcoinKey
    EXT_KEY_CLASS = bitcointx.wallet.CBitcoinExtKey


class TestNetParams(bitcointx.core.CoreTestNetParams, _ParamsTag):
    RPC_PORT = 18332
    ADDRESS_CLASS = bitcointx.wallet.CBitcoinTestnetAddress
    KEY_CLASS = bitcointx.wallet.CBitcoinTestnetKey
    EXT_KEY_CLASS = bitcointx.wallet.CBitcoinTestnetExtKey


class RegTestParams(bitcointx.core.CoreRegTestParams, _ParamsTag):
    RPC_PORT = 18443
    ADDRESS_CLASS = bitcointx.wallet.CBitcoinTestnetAddress
    KEY_CLASS = bitcointx.wallet.CBitcoinTestnetKey
    EXT_KEY_CLASS = bitcointx.wallet.CBitcoinTestnetExtKey


"""Master global setting for what chain params we're using.

However, don't set this directly, use SelectParams() instead so as to set the
bitcointx.core.params correctly too.
"""

params = MainParams()


@contextmanager
def ChainParams(name):
    """Context manager to temporarily switch chain parameters.

    Switching chain parameters involves setting global variables
    and parameters of certain classes. NOT thread-safe.
    """
    global params
    prev_params_name = params.NAME
    SelectParams(name)
    try:
        yield
    finally:
        SelectParams(prev_params_name)


def SelectAlternativeParams(alt_core_params, alt_main_params):
    """Select alternative chain parameters to use

    alt_core_params should be a subclass of core.CoreChainParamsBase,
    but redefine all fields

    alt_main_params should be a subclass of alt_core_params,
    and define all fields that are defined in MainParams

    """
    global params

    bitcointx.core._SelectAlternativeCoreParams(alt_core_params)
    bitcointx.core.script._SetScriptClassParams(
        alt_main_params.ADDRESS_CLASS._script_class)
    bitcointx.wallet._SetAddressClassParams(alt_main_params.ADDRESS_CLASS,
                                            alt_main_params.KEY_CLASS,
                                            alt_main_params.EXT_KEY_CLASS)

    assert(issubclass(alt_main_params, alt_core_params))

    params = alt_main_params()


def SelectParams(name):
    """Select the chain parameters to use

    name is one of 'mainnet', 'testnet', or 'regtest'

    Default chain is 'mainnet'

    Switching chain parameters involves setting global variables
    and parameters of certain classes. NOT thread-safe.
    """
    if name.startswith('sidechain/'):
        params_pair = bitcointx.sidechain.get_chain_params(name)
        assert len(params_pair) == 2
        SelectAlternativeParams(*params_pair)
        return

    coreparams = bitcointx.core._CoreParamsByName(name)

    for cls in _ParamsTag.__subclasses__():
        if name == cls.NAME:
            SelectAlternativeParams(coreparams, cls)
            return

    raise ValueError('Unknown chain %r' % name)
