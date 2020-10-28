[![Package version](https://img.shields.io/pypi/v/python-bitcointx.svg)](https://pypi.python.org/pypi/python-bitcointx)
[![Package license](https://img.shields.io/pypi/l/python-bitcointx.svg)](https://pypi.python.org/pypi/python-bitcointx)
[![Python versions](https://img.shields.io/pypi/pyversions/python-bitcointx.svg)](https://pypi.python.org/pypi/python-bitcointx)
[![Build Status](https://travis-ci.org/Simplexum/python-bitcointx.svg?branch=master)](https://pypi.python.org/pypi/python-bitcointx)

# python-bitcointx

This Python3 library provides an easy interface to the bitcoin transaction data
structures. This is based on https://github.com/petertodd/python-bitcoinlib,
but is focused only on providing the tools to build, manipulate and sign
bitcoin transactions, and related data structures.

It does not aim to be "The Swiss Army Knife of the Bitcoin protocol", but rather
be a more specialized tool for handling transactions and associated data, with
a focus on correctness, consistency, and developer ergonomics.

## Notable differences from python-bitcoinlib

* Network-related code that deals with network messages and blocks is removed.
* Some API have changed and may be not compatible with old code (see below)
* libsecp256k1 is used for signing and verifying.
  Signing by libsecp256k1 is deterministic, per RFC6979.
* Support for PSBT (BIP174 Partially-signed transactions)
* HD keys support
* Easier to build code that supports and interacts with other bitcoin-based blockchains
  (see https://github.com/Simplexum/python-litecointx and https://github.com/Simplexum/python-elementstx)
* A wrapper for `libbitcoinconsensus`'s script verification function is included
* RPC API wrapper is 'raw' - does not convert the results of the calls to the library objects.
* Fully type-annotated and statically checked with [mypy](https://github.com/python/mypy)

## Note on v1.0.0 release

The switch from v0.10.x to v1.0.0 was done because of the big refactoring effort
that was made to improve the consistency of the library API, make it more composeable and maintainable.
This required significant API breakage, and it made sense to bump the version.

The first release of the v1.0.x version introduced significant amount of new code (note that any new code compes with possibility of new bugs), and increased the differences from python-bitcoinlib.

This [long post](https://gist.github.com/dgpv/6607c7d0eff66c387d8a5eaeb378e787#file-on-release-of-python-bitcointx-v1-0-1-md)
elaborates on the motivations behind the decisions that shaped
the library and v1.0.0 release in particular, and also has some code examples.

## Requirements

- Python >= 3.6
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
- [libbitcoinconsensus](https://github.com/bitcoin/bitcoin/blob/master/doc/shared-libraries.md) (optional, for consensus-compatible script verification)
- [openssl](https://github.com/openssl/openssl) (optional, only for historical signatures verification)

## Installation

```
$ pip install python-bitcointx
```

```
$ pipenv install python-bitcointx
```

```
$ poetry add python-bitcointx
```

## Structure

Everything consensus critical is found in the modules under bitcointx.core. This
rule is followed pretty strictly, for instance chain parameters are split into
consensus critical and non-consensus-critical.

    bitcointx.core            - Basic core definitions, datastructures, and
                                (context-independent) validation
    bitcointx.core.key        - ECC keys, BIP32Paths
    bitcointx.core.script     - Scripts and opcodes
    bitcointx.core.scripteval - Script evaluation/verification
    bitcointx.core.psbt       - BIP174 Partially-signed transactions
    bitcointx.core.serialize  - Serialization
    bitcointx.core.secp256k1  - functions to interface with secp256k1 C library
                                (Note: to safely use it, experience with C
                                and understanting of python-C interop is a must)
    bitcointx.core.sha256     - (Slow) python implementation of SHA256,
                                but with ability to get SHA256 mid-state
    bitcointx.core.bitcoinconsensus
                              - ctypes wrapping code for libbitcoinconsensus script
                                verification function, with interface compatible
                                with VerifyScript from bitcointx.core.scripteval

Note that this code does not aim to be fully consensus-compatible with current
bitcoin core codebase. Corner cases that is not relevant to creating valid bitcoin
transactions is unlikely to be considered. See also note on VerifyScript usage below.

Non-consensus critical modules include the following:

    bitcointx          - Chain selection
    bitcointx.base58   - Base58 encoding
    bitcointx.bech32   - Bech32 encoding
    bitcointx.rpc      - Bitcoin Core RPC interface support
    bitcointx.wallet   - Wallet-related code, currently Bitcoin address and
                         private key support
    bitcointx.util     - various code-related utitlity classes and functions

Effort has been made to follow the Satoshi source relatively closely, for
instance Python code and classes that duplicate the functionality of
corresponding Satoshi C++ code uses the same naming conventions: CTransaction,
CPubKey, nValue etc. Otherwise Python naming conventions are followed.

## Mutable vs. Immutable objects

Like the Bitcoin Core codebase CTransaction is immutable and
CMutableTransaction is mutable; unlike the Bitcoin Core codebase this
distinction also applies to COutPoint, CTxIn, CTxOut and CTxWitness.

## Endianness Gotchas

Rather confusingly Bitcoin Core shows transaction and block hashes as
little-endian hex rather than the big-endian the rest of the world uses for
SHA256. python-bitcointx provides the convenience functions x() and lx() in
bitcointx.core to convert from big-endian and little-endian hex to raw bytes to
accomodate this. In addition see b2x() and b2lx() for conversion from bytes to
big/little-endian hex.

## API changes vs python-bitcoinlib

Note: only public API changes is listed here

* `CBitcoinAddress(<testnet_or_regtest_address>)` won't work: you will need to use `CCoinAddress` (universal, the class of returned instance depends on current chain params), or `CBitcoinTestnetAddress`/`CBitcoinRegtestAddress` directly. `CBitcoinAddress` is used only for Bitcoin mainnet addresses.
* `rpc.Proxy` removed, `rpc.RPCCaller` added (same as old `rpc.RawProxy`, but `btc_conf_file` kwarg renamed to just `conf_file`). If old rpc.Proxy functionality is desired, it should be implemented as a separate library.
* `CTransaction` default version changed to 2
* `CPubKey.is_valid`, `CPubKey.is_fullyvalid` and `CPubKey.is_compressed` should now be called as methods: `pub.is_valid()`, not `pub.is_valid`. `CPubKey.is_valid()` is also deprecated, and `CPubKey.is_nonempty()` should be used instead, to avoid possible confusion `is_valid()`/`is_fullyvalid()`.
* `CBitcoinAddressError` is removed, `CCoinAddressError` should be used instead
* Chain params for bitcoin is renamed, instead of 'mainnet', 'testnet', 'regtest' it is now 'bitcoin', 'bitcoin/testnet', 'bitcoin/mainnet'
* `CBech32Data.from_bytes` - changed arg order, witver is now kwarg
* `CTxWitness` is now immutable, `CMutableTxWitness` is added.
* If mutable components supplied to CTransaction, they will be internally converted to immutable, and vise versa with CMutableTransaction
* string representations (returned by `repr` and `str`) of various objects will often differ from that of python-bitcoinlib's.
* `COIN`, `MAX_MONEY`, etc. moved to `CoreCoinParams` class, that can be
subclassed and will be dispatched similar to `CTransaction` and friends. It is recommended to use `MoneyRange()` and `coins_to_satoshi()`, `satoshi_to_coins()` functions. The two former functions will also raise ValueError if supplied/returned value is outside of MoneyRange. (unless `check_range=False` is passed)
* `MoneyRange()` function does not accept `params=` argument anymore. To get money range for different params, you can use `with ChainParams():`.

## Note on VerifyScript() usage

`VerifyScript()` in `bitcointx.core.scripteval` is (incomplete) python implementation
of Bitcoin script interpreter. It may be useful for debugging purposes.

But! Bitcoin Core should _always_ remain the authoritative source on bitcoin
transaction inputs validity.

If you want script verification with consensus rules, you should use libbitcoinconsensus
(https://github.com/bitcoin/bitcoin/blob/master/doc/shared-libraries.md), available
via `ConsensusVerifyScript()` in `bitcointx.core.bitcoinconensus`.

Script evaluation code of VerifyScript() is NOT in sync with Bitcoin Core code,
and lacks some features. While some effort was made to make it behave closer
to the code in Bitcoin Core, full compatibility is far away, and most likely
will not be ever achieved.

**WARNING**: DO NOT rely on VerifyScript() in deciding if certain signed
transaction input is valid.  In some corner cases (non-standard signature encoding,
unhandled script evaluation flags, etc) it may deem something invalid that bitcoind
would accept as valid.  More importanty, it could accept something as valid
that bitcoind would deem invalid. `ConsensusVerifyScript()` should be suitable for
that purpose, as it is just a thin wrapper over the C library `libbitcoinconsensus`.

## Module import style

While not always good style, it's often convenient for quick scripts if
`import *` can be used. To support that all the modules have `__all__` defined
appropriately.


# Example Code

See `examples/` directory. For instance this example creates a transaction
spending a pay-to-script-hash transaction output:

    $ PYTHONPATH=. examples/spend-pay-to-script-hash-txout.py
    <hex-encoded transaction>


## Selecting the chain to use

Do the following:

    import bitcointx
    bitcointx.select_chain_params(NAME)

Where NAME is one of 'bitcoin', 'bitcoin/testnet', or 'bitcoin/regtest'.
The chain parameters currently selected is a thread-local variable that changes
behavior everywhere. If you need to change the parameters temporary, you can use
`ChainParams` context manager. To get current chain params, you can use
`get_current_chain_params()`:

```python
from bitcointx import ChainParams
with ChainParams('bitcoin/testnet') as params:
    print(f"{params.readable_name} params ({params.name}) are in effect")
```
will print

```
Bitcoin testnet params (bitcoin/testnet) are in effect
```

## Unit tests

Under bitcointx/tests using test data from Bitcoin Core. To run them:

    python3 -m unittest discover

Alternately, if Tox (see https://tox.readthedocs.org/) is available on your
system, you can run unit tests for multiple Python versions:

    ./runtests.sh

Currently, the following implementations are tried (any not installed are
skipped):

    * CPython 3.6
    * CPython 3.7
    * CPython 3.8-dev

HTML coverage reports can then be found in the htmlcov/ subdirectory.

## Documentation

Sphinx documentation is in the "doc" subdirectory. Run "make help" from there
to see how to build. You will need the Python "sphinx" package installed.

Currently this is just API documentation generated from the code and
docstrings. Higher level written docs would be useful, perhaps starting with
much of this README. Pages are written in reStructuredText and linked from
index.rst.
