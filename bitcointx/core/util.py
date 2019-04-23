# Copyright (C) 2018-2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.


class _NoBoolCallable():
    def __init__(self, value):
        self.value = value

    def __int__(self):
        raise TypeError(
            'Using this attribute as integer property is disabled. '
            'please use <obj>.{}()')

    def __bool__(self):
        raise TypeError(
            'Using this attribute as boolean property is disabled. '
            'please use <obj>.{}()')

    def __call__(self):
        return self.value


def _disable_boolean_use(f):
    """A decorator that disables use of an attribute
    as a property in a boolean context """
    @property
    def wrapper(self, *args, **kwargs):
        value = f(self, *args, **kwargs)
        return _NoBoolCallable(value)
    return wrapper
