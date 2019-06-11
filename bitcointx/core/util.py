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

from abc import ABCMeta


class _NoBoolCallable():
    __slots__ = ['method_name', 'value']

    def __init__(self, name, value):
        self.method_name = name
        self.value = value

    def __int__(self):
        raise TypeError(
            'Using this attribute as integer property is disabled. '
            'please use {}()'.format(self.method_name))

    def __bool__(self):
        raise TypeError(
            'Using this attribute as boolean property is disabled. '
            'please use {}()'.format(self.method_name))

    def __call__(self):
        return self.value


def no_bool_use_as_property(f):
    """A decorator that disables use of an attribute
    as a property in a boolean context """
    @property
    def wrapper(self, *args, **kwargs):
        value = f(self, *args, **kwargs)
        name = '{}().{}'.format(self.__class__.__name__, f.__name__)
        return _NoBoolCallable(name, value)
    return wrapper


def set_frontend_class(frontend_cls, concrete_cls, frontend_class_store):
    if not issubclass(concrete_cls, frontend_cls):
        raise ValueError(
            '{} is was not registered as {} subclass'
            .format(concrete_cls.__name__, frontend_cls.__name__))

    if not hasattr(frontend_class_store, 'clsmap'):
        frontend_class_store.clsmap = {}

    frontend_class_store.clsmap[frontend_cls] = concrete_cls


def make_frontend_metaclass(prefix, frontend_class_store):
    def base_new(cls, *args, **kwargs):
        if cls not in frontend_class_store.clsmap:
            raise TypeError(
                'Concrete implementation for {} is not defined for current '
                'chain parameters'.format(cls.__name__))
        real_class = frontend_class_store.clsmap[cls]
        return real_class(*args, **kwargs)

    base_class = type(prefix + 'FrontendClassBase', (), {'__new__': base_new})
    meta_class = type(prefix + 'FrontendClassMeta', (ABCMeta, ), {})

    def meta_getattr(cls, name):
        if cls not in frontend_class_store.clsmap:
            raise TypeError(
                'Concrete implementation for {} is not defined for current '
                'chain parameters'.format(name))
        real_class = frontend_class_store.clsmap[cls]
        return getattr(real_class, name)

    meta_class.__getattr__ = meta_getattr

    def meta_new(cls, name, bases, dct):
        if any(type(b) is cls for b in bases):
            # If there are base class that has our metaclass as a type,
            # that means we do not need to add *FrontendClassBase,
            # because everything is already in place at this base class
            pass
        else:
            # otherwise, we add the base class
            bases = tuple([base_class] + list(bases))
        return super(meta_class, cls).__new__(cls, name, bases, dct)

    meta_class.__new__ = meta_new

    return meta_class
