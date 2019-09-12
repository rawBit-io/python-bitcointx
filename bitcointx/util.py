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
import functools
from types import FunctionType
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


def get_class_dispatcher_depends(dclass):
    """Return a set of dispatcher the supplied dispatcher class depends on"""
    dset = set()

    for dep_dclass in dclass._class_dispatcher__depends:
        dset.add(dep_dclass)
        dset |= get_class_dispatcher_depends(dep_dclass)

    assert len(dset) == len(set([elt._class_dispatcher__identity
                                 for elt in dset])), \
        "all the dispatcher in the set must have distinct identities"

    return dset


def activate_class_dispatcher(dclass):
    """Activate particular class dispatcher - so that the mapping it contains
    will be active. Activates its dependent dispatchers, recursively, too."""
    assert ClassMappingDispatcher in dclass.__mro__

    if dclass._class_dispatcher__no_direct_use:
        raise ValueError("{} must not be used directly"
                         .format(dclass.__name__))

    prev = getattr(class_mapping_dispatch_data,
                   dclass._class_dispatcher__identity)

    if dclass is not prev:
        for ddep in get_class_dispatcher_depends(dclass):
            activate_class_dispatcher(ddep)

        setattr(class_mapping_dispatch_data,
                dclass._class_dispatcher__identity,
                dclass)

    return prev


def dispatcher_mapped_list(cls):
    """Get a list of the classes that particular class is to be
    dispatched to. Returns empty list when class is not in a dispatch map"""
    mcs = type(cls)
    if ClassMappingDispatcher not in mcs.__mro__:
        raise ValueError('{} is not a dispatcher class'.format(cls.__name__))

    dispatcher = getattr(class_mapping_dispatch_data,
                         mcs._class_dispatcher__identity)

    return dispatcher._class_dispatcher__clsmap.get(cls, [])


class DispatcherMethodWrapper():
    """A helper class that allows to wrap both classmethods and staticmethods,
    in addition to normal instance methods"""
    def __init__(self, method, wrapper):
        self.method = method
        self.wrapper = wrapper

    def __get__(self, instance, owner):
        bound_method = self.method.__get__(instance, owner)
        return self.wrapper(bound_method, type(owner))


def dispatcher_wrap_methods(cls, wrap_fn, *, dct=None):
    """Wrap all methods of a class with a function, that would
    establish the dispatching context for that method"""
    if dct is None:
        dct = cls.__dict__

    for attr_name, attr_value in dct.items():
        if isinstance(attr_value, (FunctionType, classmethod, staticmethod,
                                   DispatcherMethodWrapper)):
            setattr(cls, attr_name,
                    DispatcherMethodWrapper(attr_value, wrap_fn))


class ClassMappingDispatcher(ABCMeta):
    """A custom class dispatcher that translates invocations and attribute
    access of a superclass to a certain subclass according to internal map.
    This map is built from the actual superclass-subclass relations between
    the classes, with the help of a few additional flags that control the
    final mapping"""

    def __init_subclass__(mcs, identity=None, depends=()):
        """Initialize the dispatcher metaclass.
           Arguments:
                identity:
                    a string that sets the identity of the mapping:
                    the module that this mapping belongs to
                    (core, wallet, script, ...)
                    if identity is specified, that means that this is a
                    'base dispatcher' - it cannot be used directly,
                    and must be subclassed. Subclasses of the base
                    dispatcher cannot set their own identity, they all
                    will use the same identity set for the base dispatcher.
                depends:
                    a list of dispatchers that this dispatcher depends on.
                    the current dispatcher may directly use classes dispatched
                    by the dependent dispatchers, or the dependency may be
                    'structural' - as WalletBitcoinDispatcher, when activated,
                    implies that CoreBitcoinDispatcher should also be
                    activated, along with ScriptBitcoinDispatcher, for the
                    class dispatching situation to be consistent.
            """

        # metaclass attributes pollute the namespace of all the classes
        # that use the metaclass.
        # Use '_class_dispatcher__' prefix to minimize pollution.

        if identity is not None:
            if not hasattr(class_mapping_dispatch_data, identity):
                raise ValueError('identity {} is not recognized'
                                 .format(identity))
            if hasattr(mcs, '_class_dispatcher__identity'):
                raise AssertionError("can't replace identity that was already "
                                     "set by the base class")
            mcs._class_dispatcher__identity = identity
            mcs._class_dispatcher__no_direct_use = True
            mcs._class_dispatcher__pre_final_dispatch = set()
            mcs._class_dispatcher__depends = depends
            for ddisp in depends:
                if not issubclass(ddisp, ClassMappingDispatcher):
                    raise TypeError('{} is not a dispatcher class'
                                    .format(ddisp.__name__))
            return

        if not getattr(mcs, '_class_dispatcher__identity', None):
            raise TypeError(
                "identity attribute is not set for the base dispatcher class")

        mcs._class_dispatcher__final_dispatch = set()
        mcs._class_dispatcher__no_direct_use = False
        mcs._class_dispatcher__clsmap = {}

        if depends:
            parent_depends = mcs._class_dispatcher__depends
            combined_depends = list(mcs._class_dispatcher__depends)
            for ddisp in depends:
                replaced_index = None
                for i, pdep in enumerate(parent_depends):
                    if issubclass(ddisp, pdep):
                        if combined_depends[i] != pdep:
                            raise TypeError(
                                '{} is specified in depends argument, but '
                                'it is in conflict with {}, that also tries '
                                'to replace {} from parent depenrs'
                                .format(ddisp, combined_depends[i], pdep))
                        if replaced_index is not None:
                            raise TypeError(
                                '{} is specified in depends argument, but '
                                'it is a subclass of both {} and {}'
                                .format(ddisp, parent_depends[replaced_index],
                                        pdep))
                        combined_depends[i] = ddisp
                        replaced_index = i

                if replaced_index is None:
                    raise TypeError(
                        '{} is specified in depends argument, but it is not '
                        'a subclass of any dependencies of the parent of {}'
                        .format(ddisp, mcs))

            mcs._class_dispatcher__depends = tuple(combined_depends)

    def __new__(mcs, name, bases, dct, next_dispatch_final=False,
                variant_of=None):
        return super().__new__(mcs, name, bases, dct)

    def __init__(cls, name, bases, dct, next_dispatch_final=False,
                 variant_of=None):
        """Build the dispatching map out of the superclass-subclass
        relationships, and wrap the methods of the classes so that appropriate
        dispatcher is active inside the methods.
            Arguments:
                next_dispatch_final:
                    if True, means that this class should be mapped to
                    a single subclass, the mapping cannot be ambiguous.
                    If there's more than one subclasses, only one, 'default'
                    subclass may be in the mapping, an all other should
                    specify variant_of=<default_subclass>
                variant_of:
                    specifies another class that cls is a variant of,
                    when cls is not the default mapping for the superclass
                    that was marked with next_dispatch_final=True"""

        super().__init__(name, bases, dct)

        # get the dispatcher class
        mcs = type(cls)

        # Wrap all methods of a class to enable the relevant dispatcher
        # within the methods.
        # For example, inside CBitcoinTransaction.deserialize(), CTxOut()
        # should produce CBitcoinTxOut, regardless of the current globally
        # chosen chain parameters.
        def wrap(fn, mcs):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                if mcs._class_dispatcher__no_direct_use:
                    # The method of the class assigned to base dispatcher is
                    # called. Base dispatcher cannot be activated, so we
                    # just call the method.
                    # This happens when the base class is mapped to several
                    # subclasses, and the methods in the base class are
                    # supposed to do their own dispatching, using
                    # dispatcher_mapped_list function.
                    return fn(*args, **kwargs)

                prev_dispatcher = activate_class_dispatcher(mcs)
                try:
                    return fn(*args, **kwargs)
                finally:
                    activate_class_dispatcher(prev_dispatcher)

            return wrapper

        dispatcher_wrap_methods(cls, wrap)

        if next_dispatch_final:
            # for correctness, the classes that are not meant to be
            # dispatched to multiple candidate classes, but should only
            # have a mapping to one particular class, need to be marked
            # with next_dispatch_final=True parameter.
            # Here we store these classes to the set, to enable checking
            # the subsequent mappings against this set.
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

            target_list = mcs._class_dispatcher__clsmap.get(bcs, [])

            if any(issubclass(cls, target_cls) for target_cls in target_list):
                # if the mapped list contains a superclass of the
                # current class, do not add the class to the set, so that only
                # the direct subclasses will be in the mapping
                continue

            if variant_of is not None and variant_of in target_list:
                # If the class is a variant of the class that is already
                # is the target of the maping of some class, skip it
                continue

            if bcs in mcs._class_dispatcher__pre_final_dispatch:
                # if the class is a subclass of pre_final_dispatch class,
                # it is itself a final target of the dispatch.
                mcs._class_dispatcher__final_dispatch.add(cls)

                # check for correctness in regard to next_dispatch_final param
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
            # assign to the map in case this is first time
            mcs._class_dispatcher__clsmap[bcs] = target_list

    def __call__(cls, *args, **kwargs):
        """Perform class mapping in accordance to the currently active
        dispatcher class"""
        mcs = type(cls)
        cur_dispatcher = getattr(class_mapping_dispatch_data,
                                 mcs._class_dispatcher__identity)
        if cur_dispatcher is None:
            return type.__call__(cls, *args, **kwargs)

        class_list = cur_dispatcher._class_dispatcher__clsmap.get(cls, [])
        if len(class_list) != 1:
            # There is more than one target, so this is not
            # a final mapping. Instantiate the original class, and allow
            # it to do its own dispatching.
            return type.__call__(cls, *args, **kwargs)
        # Unambigous target - do the substitution.
        return type.__call__(class_list[0], *args, **kwargs)

    def __getattribute__(cls, name):
        """Perform class attribute mapping in accordance to the currently
        active dispatcher class (except python-specific attributes)"""
        if name.startswith('__') and name.endswith('__'):
            return type.__getattribute__(cls, name)
        mcs = type(cls)
        cur_dispatcher = getattr(class_mapping_dispatch_data,
                                 mcs._class_dispatcher__identity)
        if cur_dispatcher is None:
            return type.__getattribute__(cls, name)

        class_list = cur_dispatcher._class_dispatcher__clsmap.get(cls, [])
        if len(class_list) != 1:
            # There is more than one target, so this is not
            # a final mapping. The original class is doing
            # its own dispatching, and we do not need to do any
            # attribute substition here.
            return type.__getattribute__(cls, name)
        # Unambigous target - do the substitution.
        return getattr(class_list[0], name)


class classgetter:
    """simple decorator to create a read-only class property
    from class method"""

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)
