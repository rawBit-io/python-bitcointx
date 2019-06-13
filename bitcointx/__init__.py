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

import os
import platform

from abc import ABCMeta
from contextlib import contextmanager
from collections import OrderedDict

import bitcointx.core
import bitcointx.core.script
import bitcointx.wallet

# Note that setup.py can break if __init__.py imports any external
# dependencies, as these might not be installed when setup.py runs. In this
# case __version__ could be moved to a separate version.py and imported here.
__version__ = '1.0.0'


class ChainParamsMeta(ABCMeta):
    _required_attributes = (
        ('MAX_MONEY', isinstance, int),
        ('NAME', isinstance, str),
        ('RPC_PORT', isinstance, int),
        ('CONFIG_LOCATION', isinstance, tuple),
        ('TRANSACTION_IDENTITY',
         issubclass, bitcointx.core.CoinTransactionIdentityMeta),
        ('ADDRESS_CLASS', issubclass, bitcointx.wallet.CCoinAddress),
        ('KEY_CLASS', issubclass, bitcointx.wallet.CCoinKey),
        ('EXT_KEY_CLASS', issubclass, bitcointx.wallet.CCoinExtKey)
    )
    _registered_classes = OrderedDict()
    _common_base_cls = None

    def __new__(cls, cls_name, bases, dct):
        cls_instance = super(ChainParamsMeta, cls).__new__(cls, cls_name,
                                                           bases, dct)

        if len(bases):
            if not any(issubclass(b, cls._common_base_cls) for b in bases):
                raise TypeError(
                    '{} must be a subclass of {}'.format(
                        cls_name, cls._common_base_cls.__name__))
            for attr_name, checkfn, checkarg in cls._required_attributes:
                if attr_name not in dct:
                    # Attribute will be inherited from the base class
                    continue
                if not checkfn(dct[attr_name], checkarg):
                    raise TypeError(
                        '{}.{} failed {} check against {}'
                        .format(cls_name, attr_name, checkfn.__name__,
                                checkarg.__name__))

            cls._registered_classes[cls_instance.NAME] = cls_instance
        else:
            if cls._common_base_cls:
                raise TypeError(
                    '{} cannot be used with more than one class, '
                    '{} was here first'.format(cls.__name__,
                                               cls._common_base_cls))
            cls._common_base_cls = cls_instance

        return cls_instance

    @classmethod
    def find_chain_params(cls, *, name=None):
        return cls._registered_classes.get(name)

    @classmethod
    def get_registered_chain_params(cls):
        return cls._registered_classes.values()


class ChainParamsBase(metaclass=ChainParamsMeta):
    """All chain param classes must be a subclass of this class."""

    def get_confdir_path(self):
        """Return default location for config directory"""
        name = self.NAME.split('/')[0]

        if platform.system() == 'Darwin':
            return os.path.expanduser(
                '~/Library/Application Support/{}'.format(name.capitalize()))
        elif platform.system() == 'Windows':
            return os.path.join(os.environ['APPDATA'], name.capitalize())

        return os.path.expanduser('~/.{}'.format(name))

    def get_config_path(self):
        """Return default location for config file"""
        name = self.NAME.split('/')[0]
        return '{}/{}.conf'.format(self.get_confdir_path(), name)

    def get_datadir_extra_name(self):
        """Return appropriate dir name to find data for the chain,
        and .cookie file. For mainnet, it will be an empty string -
        because data directory is the same as config directory.
        For others, like testnet or regtest, it will differ."""
        name_parts = self.NAME.split('/')
        if len(name_parts) == 1:
            return ''
        return name_parts[1]

    def get_readable_name(self):
        name_parts = self.NAME.split('/')
        name_parts[0] = name_parts[0].capitalize()
        return ' '.join(name_parts)


class BitcoinMainnetParams(ChainParamsBase):
    RPC_PORT = 8332
    MAX_MONEY = 21000000 * bitcointx.core.COIN
    NAME = 'bitcoin'
    TRANSACTION_IDENTITY = bitcointx.core.BitcoinTransactionIdentityMeta
    ADDRESS_CLASS = bitcointx.wallet.CBitcoinAddress
    KEY_CLASS = bitcointx.wallet.CBitcoinKey
    EXT_KEY_CLASS = bitcointx.wallet.CBitcoinExtKey


class BitcoinTestnetParams(BitcoinMainnetParams):
    RPC_PORT = 18332
    NAME = 'bitcoin/testnet'
    ADDRESS_CLASS = bitcointx.wallet.CBitcoinTestnetAddress
    KEY_CLASS = bitcointx.wallet.CBitcoinTestnetKey
    EXT_KEY_CLASS = bitcointx.wallet.CBitcoinTestnetExtKey


class BitcoinRegtestParams(BitcoinMainnetParams):
    RPC_PORT = 18443
    NAME = 'bitcoin/regtest'
    ADDRESS_CLASS = bitcointx.wallet.CBitcoinRegtestAddress
    KEY_CLASS = bitcointx.wallet.CBitcoinRegtestKey
    EXT_KEY_CLASS = bitcointx.wallet.CBitcoinRegtestExtKey


def CurrentChainParams():
    return bitcointx.core._CurrentChainParams()


@contextmanager
def ChainParams(params):
    """Context manager to temporarily switch chain parameters.
    """
    prev_params = CurrentChainParams()
    SelectChainParams(params)
    try:
        yield
    finally:
        SelectChainParams(prev_params)


def SelectChainParams(params):
    """Select the chain parameters to use

    name is one of 'mainnet', 'testnet', or 'regtest'

    Default chain is 'mainnet'

    Switching chain parameters involves setting global variables
    and parameters of certain classes. NOT thread-safe.
    """

    if isinstance(params, str):
        params_cls = ChainParamsMeta.find_chain_params(name=params)
        if params_cls is None:
            raise ValueError('Unknown chain %r' % params)
        params = params_cls()
    elif isinstance(params, type):
        params = params()

    if not isinstance(params, ChainParamsBase):
        raise ValueError('Supplied chain params is not a subclass of '
                         'ChainParamsBase')

    bitcointx.wallet._SetAddressClassParams(params.ADDRESS_CLASS,
                                            params.KEY_CLASS,
                                            params.EXT_KEY_CLASS)
    bitcointx.core.script._SetScriptClassParams(
        params.ADDRESS_CLASS._script_class)
    bitcointx.core._SetChainParams(params)


SelectChainParams(BitcoinMainnetParams)
