# python-bitcointx

This Python3 library provides an easy interface to the bitcoin data
structures. This is based on https://github.com/petertodd/python-bitcoinlib,
but is focused only on providing the tools to build, manipulate and sign
bitcoin transactions, and related data structures. Network-related code
that deals with sending and receiving data from and to bitcoin nodes is removed.
Bech32 segwit address support and RFC6979 signing with libsecp256k1 are added.

"The Swiss Army Knife of the Bitcoin protocol." - Wladimir J. van der Laan


## Requirements

    sudo apt-get install libssl-dev

The RPC interface, `bitcointx.rpc`, is designed to work with Bitcoin Core v0.16.0.
Older versions may work but there do exist some incompatibilities.


## Structure

Everything consensus critical is found in the modules under bitcointx.core. This
rule is followed pretty strictly, for instance chain parameters are split into
consensus critical and non-consensus-critical.

    bitcointx.core            - Basic core definitions, datastructures, and
                                (context-independent) validation
    bitcointx.core.key        - ECC pubkeys
    bitcointx.core.script     - Scripts and opcodes
    bitcointx.core.scripteval - Script evaluation/verification
    bitcointx.core.serialize  - Serialization

In the future the bitcointx.core may use the Satoshi sourcecode directly as a
library. Non-consensus critical modules include the following:

    bitcointx          - Chain selection
    bitcointx.base58   - Base58 encoding
    bitcointx.rpc      - Bitcoin Core RPC interface support (may also be stripped later)
    bitcointx.wallet   - Wallet-related code, currently Bitcoin address and
                         private key support

Effort has been made to follow the Satoshi source relatively closely, for
instance Python code and classes that duplicate the functionality of
corresponding Satoshi C++ code uses the same naming conventions: CTransaction,
CBlockHeader, nValue etc. Otherwise Python naming conventions are followed.


## Mutable vs. Immutable objects

Like the Bitcoin Core codebase CTransaction is immutable and
CMutableTransaction is mutable; unlike the Bitcoin Core codebase this
distinction also applies to COutPoint, CTxIn, CTxOut, and CBlock.


## Endianness Gotchas

Rather confusingly Bitcoin Core shows transaction and block hashes as
little-endian hex rather than the big-endian the rest of the world uses for
SHA256. python-bitcointx provides the convenience functions x() and lx() in
bitcointx.core to convert from big-endian and little-endian hex to raw bytes to
accomodate this. In addition see b2x() and b2lx() for conversion from bytes to
big/little-endian hex.


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
    bitcointx.SelectParams(NAME)

Where NAME is one of 'testnet', 'mainnet', or 'regtest'. The chain currently
selected is a global variable that changes behavior everywhere, just like in
the Satoshi codebase.

## Using libsecp256k1 for signing

It is possible to use libsecp256k1 for signing, but it have to be enabled manually, at this time.

The relevant functions are is_libsec256k1_available() and use_libsecp256k1_for_signing(do_use)
NOTE: libsecp256k1 will likely become default and required for signing,
      and this functions will be removed then.

refer to Test_RFC6979() in bitcointx/tests/test_wallet.py for example of usage.


## Unit tests

Under bitcointx/tests using test data from Bitcoin Core. To run them:

    python -m unittest discover && python3 -m unittest discover

Please run the tests on both Python2 and Python3 for your pull-reqs!

Alternately, if Tox (see https://tox.readthedocs.org/) is available on your
system, you can run unit tests for multiple Python versions:

    ./runtests.sh

Currently, the following implementations are tried (any not installed are
skipped):

    * CPython 3.3
    * CPython 3.4
    * CPython 3.5
    * PyPy
    * PyPy3

HTML coverage reports can then be found in the htmlcov/ subdirectory.

## Documentation

Sphinx documentation is in the "doc" subdirectory. Run "make help" from there
to see how to build. You will need the Python "sphinx" package installed.

Currently this is just API documentation generated from the code and
docstrings. Higher level written docs would be useful, perhaps starting with
much of this README. Pages are written in reStructuredText and linked from
index.rst.
