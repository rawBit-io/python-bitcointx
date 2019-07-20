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

import threading
from collections import defaultdict
from abc import ABCMeta

class_mapping_dispatch_data = threading.local()
class_mapping_dispatch_data.core = None
class_mapping_dispatch_data.wallet = None
class_mapping_dispatch_data.script = None


class _NoBoolCallable():
    __slots__ = ['method_name', 'method']

    def __init__(self, name, method):
        self.method_name = name
        self.method = method

    def __int__(self):
        raise TypeError(
            'Using this attribute as integer property is disabled. '
            'please use {}()'.format(self.method_name))

    def __bool__(self):
        raise TypeError(
            'Using this attribute as boolean property is disabled. '
            'please use {}()'.format(self.method_name))

    def __call__(self, *args, **kwargs):
        return self.method(*args, **kwargs)


class no_bool_use_as_property():
    """A decorator that disables use of an attribute
    as a property in a boolean context """

    def __init__(self, method):
        self.method = method

    def __get__(self, instance, owner):
        method = self.method.__get__(instance, owner)

        def wrapper(*args, **kwargs):
            return method(*args, **kwargs)

        name = '{}{}.{}'.format(owner.__name__,
                                '' if instance is None else '()',
                                method.__name__)
        return _NoBoolCallable(name, wrapper)


def activate_class_dispatcher(dclass):
    assert ClassMappingDispatcher in dclass.__mro__

    assert not dclass._class_dispatcher__no_direct_use,\
        "{} must not be used directly".format(dclass.__name__)

    prev = getattr(class_mapping_dispatch_data,
                   dclass._class_dispatcher__identity)

    if dclass is not prev:
        setattr(class_mapping_dispatch_data,
                dclass._class_dispatcher__identity,
                dclass)

    return prev


def dispatcher_mapped_list(cls):
    mcs = type(cls)
    if ClassMappingDispatcher not in mcs.__mro__:
        raise ValueError('{} is not a dispatcher class'.format(cls.__name__))

    dispatcher = getattr(class_mapping_dispatch_data,
                         mcs._class_dispatcher__identity)

    clsmap = dispatcher._class_dispatcher__clsmap

    if cls not in clsmap:
        raise ValueError('{} does not have a mapping in {}'
                         .format(cls.__name__, dispatcher.__name__))

    return clsmap[cls]


if not hasattr(object, '__init_subclass__'):
    class ABCMetaWithBackportedInitSubclass(ABCMeta):
        """ABCMeta class, but with backport of support of __init_subclass__
        for python versions that do not have support for pep-0487"""
        def __new__(mcs, name, bases, dct, **kwargs):

            isc = '__init_subclass__'
            if isc in dct:
                dct[isc] = classmethod(dct[isc])

            return super(ABCMetaWithBackportedInitSubclass,
                         mcs).__new__(mcs, name, bases, dct)

        def __init__(cls, name, bases, dct, **kwargs):
            super(ABCMetaWithBackportedInitSubclass,
                  cls).__init__(name, bases, dct)

            scls = super(cls, cls)
            if hasattr(scls, '__init_subclass__'):
                scls.__init_subclass__.__func__(cls, **kwargs)
else:
    ABCMetaWithBackportedInitSubclass = ABCMeta


class ClassMappingDispatcher(ABCMetaWithBackportedInitSubclass):

    def __init_subclass__(mcs, identity=None, no_direct_use=False):

        # metaclass attributes pollute the namespace of all the classes
        # that use the metaclass.
        # Use '_class_dispatcher__' prefix to minimize pollution.

        if identity is not None:
            assert getattr(mcs, '_class_dispatcher__identity', None) is None,\
                "can't replace identity that was already set by the base class"
            mcs._class_dispatcher__identity = identity

        if no_direct_use:
            mcs._class_dispatcher__no_direct_use = True
            mcs._class_dispatcher__final_dispatch = set()
            mcs._class_dispatcher__pre_final_dispatch = set()
            return

        mcs._class_dispatcher__no_direct_use = False
        mcs._class_dispatcher__clsmap = defaultdict(list)

    def __new__(mcs, name, bases, dct, next_dispatch_final=False,
                variant_of=None):
        return super(ClassMappingDispatcher,
                     mcs).__new__(mcs, name, bases, dct)

    def __init__(cls, name, bases, dct, next_dispatch_final=False,
                 variant_of=None):

        super(ClassMappingDispatcher, cls).__init__(name, bases, dct)

        mcs = type(cls)

        if next_dispatch_final:
            # for correctness, the classes that are not meant to be
            # dispatched to multiple candidate classes, but should only
            # have a mapping to one particular class, need to be marked
            # with next_dispatch_final=True parameter.
            # Here we store these classes to the set, to enable checking
            # the final classmap against this set.
            mcs._class_dispatcher__pre_final_dispatch.add(cls)

        if mcs._class_dispatcher__no_direct_use:
            # No need to initialize classmap, this is a base dispatcher class
            return

        # walk the bases of the class to fill the classmap
        for bcs in cls.__mro__:
            if bcs is cls:
                # skip the current class
                continue

            if ClassMappingDispatcher not in type(bcs).__mro__:
                # skip if the base does not belong to our dispatch scheme
                continue

            if bcs in mcs._class_dispatcher__final_dispatch:
                # do not map subclasses after final dispatch reached
                continue

            target_list = mcs._class_dispatcher__clsmap[bcs]

            if any(issubclass(cls, target_cls) for target_cls in target_list):
                # if the mapped set contains a superclass of the current class,
                # do not add the class to the set, so that only
                # the direct subclasses will be in the mapping
                continue

            if variant_of is not None and variant_of in target_list:
                # If the class is a variant of the class that is already
                # in the map, skip it
                continue

            # check for correctness in regard to next_dispatch_final param
            if bcs in mcs._class_dispatcher__pre_final_dispatch:
                mcs._class_dispatcher__final_dispatch.add(cls)
                if next_dispatch_final:
                    raise AssertionError(
                        '{} is marked with next_dispatch_final=True, '
                        'but {}, also marked with next_dispatch_final=Trye, '
                        'is mapped to it'.format(bcs.__name__, cls.__name__))
                if len(target_list) > 0:
                    raise AssertionError(
                        '{} is marked with next_dispatch_final=True, '
                        'adding {} to already-mapped {} will make the mapping '
                        'non-final. Maybe you want to set variant_of=... on {}'
                        .format(bcs.__name__, cls.__name__,
                                [c.__name__ for c in target_list],
                                cls.__name__))

            # add the class to the mapping
            target_list.append(cls)

    def __call__(cls, *args, **kwargs):
        mcs = type(cls)

        cur_dispatcher = getattr(class_mapping_dispatch_data,
                                 mcs._class_dispatcher__identity)

        if cur_dispatcher is None:
            return type.__call__(cls, *args, **kwargs)

        assert not cur_dispatcher._class_dispatcher__no_direct_use,\
            "{} must not be used directly".format(cur_dispatcher.__name__)

        class_list = cur_dispatcher._class_dispatcher__clsmap[cls]

        if len(class_list) != 1:
            return type.__call__(cls, *args, **kwargs)

        return type.__call__(class_list[0], *args, **kwargs)

    def __getattribute__(cls, name):
        if name.startswith('__') and name.endswith('__'):
            return type.__getattribute__(cls, name)

        mcs = type(cls)

        cur_dispatcher = getattr(class_mapping_dispatch_data,
                                 mcs._class_dispatcher__identity)

        if cur_dispatcher is None:
            return type.__getattribute__(cls, name)

        assert not cur_dispatcher._class_dispatcher__no_direct_use,\
            "{} must not be used directly".format(cur_dispatcher.__name__)

        class_list = cur_dispatcher._class_dispatcher__clsmap[cls]

        if len(class_list) != 1:
            return type.__getattribute__(cls, name)

        return getattr(class_list[0], name)
