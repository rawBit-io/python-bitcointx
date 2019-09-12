# python-bitcointx release notes

## v1.0.0

Significant changes, refactoring, API breakage.

The code is now more composable, API is more consistent,
building support for other bitcoin-based coins on top of
python-bitcointx is now much easier. See for example
[python-litecointx](https://github.com/Simplexum/python-litecointx) and
[python-elementstx](https://github.com/Simplexum/python-elementstx)

* NOTE: The switch to v1.0.0 does not signify that the library
  is in any way more 'mature' or 'stable' or 'production-ready'
  than the v0.10.x.The switch to the new major version was done purely
  because of the big refactoring effort that was made to improve
  the consistency of the library API, make it more composeable
  and maintainable. This required significant API breakage,
  and it made sense to bump the version. If anything, the first
  release of the v1.0.x version should be viewed as less mature
  than the v0.10.x, because of the amount of new code that was introduced.

* Custom class dispatching is introduced for address classes,
  keys classes, and transaction classes (`CTransaction`, `CTxIn`, etc.)
  
  For example, when you create `CTransaction`, with default chain
  params in effect, you will get an instance of `CBitcoinTransaction`.

  If you are using python-elementstx, and Elements chain params are
  in effect, you will get `CElementsSidechainTransaction`.
  Same with `CTxIn`, `CTxWitness`, and other transaction component classes,
  and also `CScript`.

  Within CBitcoinTransaction's methods, the 'bitcoin' class dispatcher will
  always be active, even if the global dispatcher is set to 'elements', for
  example. For example, if you need to deserialize specifically a bitcoin
  transaction, while you are working with Elements blockchain via
  python-elementstx, you can do `CBitcoinTransaction.deserialize(btc_tx_data)`,
  and you will get the correct result.
  
  To support the same abstraction for addresses, `CCoinAddress` (and
  related classes) was introduced. You can still use `CBitcoinAddress`,
  and when you use `CCoinAddress` with default chain parameters, you will
  also get `CBitcoinAddress` instances. But if you switch to testnet
  chain params, `CCoinAddress(some_addr)` will give you `CBitcoinTestnetAddress`
  instance. Note that this breaks code that expect `CBitcoinAddress` to work with
  regtest and testnet addresses. For that code to work, you will need to switch
  from `CBitcoinAddress` to `CCoinAddress`
  
  The good thing about this is that even after you switch the current chain
  parameters, the instances retain their representation in accordance to
  their class. An instance of `CBitcoinTestnetAddress` will still show up
  with testnet prefix when converted to string. With old architecture,
  that was used in python-bitcoinlib, your address instances that was
  created with testnet chain params in effect, will all automatically switch
  to 'mainnet' representation.
  
  While this may not be a serious inconvenience when working only with Bitcoin,
  if you want to build a cross-chain atomic swap code between Bitcoin and
  Elements, for example, you will need to switch back and forth between the
  chain params. And having all your addresses change their representation
  complicates things a lot. Having frontend classes and separate address
  class for each address representation makes the library and the code that
  uses it more composable, and interoperable.

  Chain parameters like `COIN` and `MAX_MONEY` moved to their own CoreCoinParams
  class, that is also being dispatched to CoreBitcoinParams, or CoreElementsParams
  in case of python-elementstx. This allows to build libraries that would support
  arbitrary changes to the core parameters, cleanly.

* Notable new classes, functions and methods
  - `AddressDataEncodingError` exception - more general than `Base58Error`
     or `Bech32Error`, and it includes them.
  - `@no_bool_use_as_property` function decorator, to be applied to methods
    like `is_something()`, that will enforce the correct usage, so that
    ```python
    if instance.is_something:
        got_someting()
    ```
    will cause `TypeError` to be raised.
    This prevents bugs by accidentally treating method as property.
    Note that method-call convention vs property convention for `is_*`
    was selected for historical reasons - in the existing code, there was
    much more method-like `is_something()` usage then property-like.
    That needed to be made consistent, but with less breakage.
    Therefore, the convention that was more used thorugh code was chosen.
    Chosing property-like convention might also cause subtle bugs when
    code written for python-bitcointx would be used with python-bitcoinlib
    or its other descendants. bool(script.is_valid) would give appropriate
    result in one case, and will be always true in other case. Thus,
    method-like is safer than property-like access to these boolean attributes.
  - `CScriptBase` now have `sighash()` and `raw_sighash()` methods,
    that return appropriate signature hash for the script instance.
    Useful when sighash implementation is not the same as Bitcoin's.
    Also, `to_p2wsh_scriptPubKey()` method was added
  - `CBitcoinSecret` is now `CCoinKey`. `CBitcoinSecret` is retained
    for compatibility, but is a subclass of bitcoin-specific `CBitcoinKey`.
    `CCoinKey` naming is more consistent with `CKey`, `CCoinExtKey`, etc.
    `CCoinKey`, `CCoinExtKey`, `CCoinExtPubKey` are frontend classes
    that will give appropriate instances according to current chain params.
    (`CBitcoinKey`, `CBitcoinTestnetExtKey`, etc.)
  - `CTransaction` and other serializable classes in `bitcointx.core`
    now have convenience methods `to_mutable()`/`to_immutable()`,
    to easily convert between mutable and immutable versions, and
    `is_mutable()`/`is_immutable()` to check for mutability.
    `serialize()` method now have `for_sighash` keywork arg - for cases
    when the serialization is different for sighash calculations (Elements)
  - ECDH, key addition and substraction
    If support in secp256k1 library is available, `CKey` has `ECDH()` method to
    compute an EC Diffie-Hellman secret.
    If support in secp256k1 library is available, `CKey` and `CPubKey` has
    classmethods `add()`, `combine()`, `sub()`, `negated()` that allow to
    perform these operations on the keys.
    `add()` is implemented thorugh `combine()`, `sub()` implemented
    using `negated()`.
  - `BIP32Path` class, `CExtKeyBase.derive_path()`, to deal with hierarchial
    deterministic derivation. For usage see `bitcointx/tests/test_hd_keys.py`
  - Guard functions for script: `DATA()`, `NUMBER()`, `OPCODE()` -
    can be used to prevent accidental use of unintended values in the script
    where certain types of values are expected. For example,
    the code `CScript([var])` does not communicate to the reader if `var`
    is expected to be just data, or a number, or an opcode.
    with `CScript([NUMBER(var)])`, it is apparent that the number is expected.
  - Uint256 class
    `bitcointx.core.Uint256` - a convenience class to represent 256-bit
    integers. have `from_int()` and `to_int()` methods.

* Classes representations for `repr()` and `str()` can significantly
  differ, with `repr()` giving more detailed view, and for example for
  confidential data in Elements blockchain, `str()` may show
  'CONFIDENTIAL', if the data cannot be meaningfully interpreted.
  `repr()` will show the data as-is.

* Misc
  - `CTransaction` default version changed to 2
  - if `bytes` is accepted by some method, `bytesarray` will be, too
  - core.script: `CHECKSEQUENCEVERIFY` added (no support in VerifyScript yet)
  - the bite before private data of extended private key must be zero.
    Bitcoin core ignores this, but the standard says that is should be zero.
    `CKeyBase.__init__()` will raise ValueError if it is not.
  - secp256k1 C library definitions moved to separate file
  - `bitcointx.core.sha256` module added - slow, python-only implementation
    of SHA256, but with useful property that it allows to get the SHA256
    mid-state. Needed for Elements, might be useful for other things.
  - CPubKey() can be instantiated without parameters
    (will return invalid pubkey instance)
  - utility functions and methods: to handle multisig scripts:
    `standard_multisig_redeem_script`, `standard_multisig_witness`,
    `parse_standard_multisig_redeem_script`; to handle amounts:
    `coins_to_satoshi`, `satoshi_to_coins`; to calculate transaction
    virtual size: `tx.get_virtual_size()`
  - bugfix in VerifyWitnessProgram (part of VerifyScript) - it was breaking on
    p2wsh, and on integer values on witness stack
  - `de()serialize` and `stream_(de)serialize` now always work with `**kwargs`
    instead of additional params being passet as dict
  - VectorSerializer `stream_(de)serialize` method signatures changed
    to match base class
  - CKeyMixin, CExtKeyMixin, CExtPubKeyMixin renamed to CKeyBase, CExtKeyBase,
    CExtPubKeyBase
  - CBase58PrefixedData, CBase58RawData merged back into CBase58Data
 
* Breaking public API changes:
    - `CBitcoinAddress(<testnet_or_regtest_address>)` won't work: you will need to use `CCoinAddress` (universal, the class of returned instance depends on current chain params), or `CBitcoinTestnetAddress`/`CBitcoinRegtest` address directly. `CBitcoinAddress` is used only for Bitcoin mainnet addresses.
    - `rpc.Proxy` removed, `rpc.RPCCaller` added - same as old `rpc.RawProxy`,
      but with some differences: btc_conf_file kwarg renamed to just conf_file;
      to use default configuration, you need to pass allow_default_conf=True.
      With allow_default_conf=True, default config can also be used as a
      fallback when conf_file is not supplied or cannot be read.
    - `CTransaction` default version changed to 2
    - `CKey.is_valid`, `CKey.is_fullyvalid` and `CKey.is_compressed`
      should now be called as methods: `key.is_valid()`, not `key.is_valid`.
    - `CBitcoinAddressError` is removed, `CCoinAddressError`
      should be used instead
    - Chain params for bitcoin is renamed, instead of 'mainnet', 'testnet',
      'regtest' it is now 'bitcoin', 'bitcoin/testnet', 'bitcoin/mainnet'.
      chain params selection functions also renamed.
      for details, see "Selecting the chain to use" section in README.md
    - `CBech32Data.from_bytes` - changed arg order, witver is now kwarg
    - `CTxWitness` is now immutable, `CMutableTxWitness` is added.
    - If mutable components supplied to `CTransaction`, they will be internally
      converted to immutable, and vise versa with `CMutableTransaction`
    - string representations (returned by `repr` and `str`) of various objects
      will often differ from that of python-bitcoinlib's.
    - `CBlock`, `CBlockHeader` and all related code is removed (leftover from
      previous cleaning of network-related code)
    - `verify` and `verify_nonstrict` methods of `CPubKey` now assert
      that supplied hash and sig are bytes or bytesarray instances
    - `COIN`, `MAX_MONEY`, etc. moved to `CoreCoinParams` class, that can be
      subclassed and will be dispatched similar to `CTransaction` and friends.
      It is recommended to use `MoneyRange()` and `coins_to_satoshi()`,
      `satoshi_to_coins()` functions. The two former functions will also
      raise ValueError if supplied/returned value is outside of MoneyRange.
      (unless `check_range=False` is passed)
    - `MoneyRange()` function does not accept `params=` argument anymore.
      To get money range for different params, you can use `with ChainParams():`.

## v0.10.3.post0

* Fix import issue with SelectParams()

## v0.10.3

**Breaking Changes**

* HD Key API changed, now it is more convenient.
  CBitcoinExtKey now is a subclass of CExtKeyMixin
  CBitcoinExtPubKey now is a subclass of CExtPubKeyMixin
  all classes for keys are instances of bytes
  see `examples/derive-hd-key.py` and b`itcointx/tests/test_hd_keys.py`

  Note that CBitcoinSecret instance is 33 bytes long if compressed,
  and 32 if not. CKey instance is always 32 bytes long.
  key.secret\_bytes is 32 bytes long in both cases.

* CBase58Data removed, replaced with CBase58PrefixedData, CBase58RawData
  CBase58PrefixedData is more generic, it works with arbitrary
  prefixes instead of 1-byte nVersion. used both for addresses and keys.

* Alternative base58 prefixes are now specified in MainParams
  via BASE58\_PREFIX\_ALIAS. see `examples/litecoin-alt-p2sh-prefix.py`.

**Other changes**

* libsecp256k1 may be built without pubkey recovery functions.
  in this case, CKey.sign\_compact() and CKey.recover\_compact()
  will not work, but it will not affect other functions.

* fix for bug when P2PKHBitcoinAddress.from\_scripPubKey is called
  for bare checksig with uncompressed pubkey - wrong address were generated.
  Relevant only for historical addresses.

* Other small fixes

## v0.10.2

* Support for bech32-encoded segwit addresses

* Support for HD keys. Modelled after Bitcoin Core classes: CExtKey, CExtPubKey,
  CBitcoinExtKey, CBitcoinExtPubKey. for usage examples,
  see examples/derive-hd-key.py and bitcointx/tests/test\_hd\_keys.py

* openssl dependency is optional, used only for verification of historical
  non-strict-DER-encoded signatures - CPubKey.verify\_nonstrict(). If not
  available, and verify\_nonstrict() is called, a RuntimeError will be raised.

* VerifyScript(): more `SCRIPT_VERIFY_*` flags are handled.
  VerifyScriptError is raised if unhandled flag is explicitly given. 
  Warning about VerifyScript not being consensus-compatible added to README.

* Make specifying alternative chain params easier with SelectAlternativeParams()
  (see examples/litecoin-alt-p2sh-prefix.py)

* CKey class has been moved from bitcointx.wallet to bitcointx.core.key
  - this is more logical and matches Bitcoin Core layout

* CECKey class was removed - it was a wrapper around OpenSSL's EC\_KEY,
  and is not needed anymore.

---

python-bitcointx is based on python-bitcoinlib

as of commit 05cbb3c9560b36cfe71bac06085a231a6244e13a 2018-04-26 06:46:09

therefore we include the 

# python-bitcoinlib release notes

## v0.10.1

Identical in every way to v0.10.0, but re-uploaded under a new version to fix a
PyPi issue.


## v0.10.0

Minor breaking change: RPC port for regtest updated to the new v0.16.0 default.

Other changes:

* Now looks for `.cookie` files in the datadir, if specified.
* Authentication in a RPC `service_url` is now parsed.
* Implemented bip-0037 version message.
* `contrib/verify-commits/` removed for now due to breakage.


## v0.9.0

Now supports segwit, which breaks the API in minor ways from v0.8.0. This
version introduces lots of new API functionality related to this, such as the
new `CScriptWitness`, `CTxInWitness`, `CTxWitness`, new segwit-specific logic
in `SignatureHash()` etc.


## v0.8.0

Major breaking API change!

While this interim release doesn't by itself include segwit support, it does
change the name of the `CTransaction/CMutableTransaction` method `GetHash()` to
`GetTxid()` to prepare for a future segwit-enabled release.  Incorrect calls to
`GetHash()` will now raise a `AttributeError` exception with an explanation.

Since this release doesn't yet include segwit support, you will need to set the
Bitcoin Core `-rpcserialversion=0` option, either as a command line argument,
or in your `bitcoin.conf` file. Otherwise the RPC interface will return
segwit-serialized transactions that this release's RPC support doesn't
understand.

Other changes:

* Cookie file RPC authentication is now supported.
* `msg_header` now correctly uses `CBlockHeader` rather than `CBlock`.
* RPC `getbalance` now supports `include_watchonly`
* RPC `unlockwallet` is now supported


## v0.7.0

Breaking API changes:

* The 'cooked' CScript iterator now returns `OP_0` for the empty binary string
  rather than `b''`

* The alias `JSONRPCException = JSONRPCError` has been removed. This alias was
  added for compatibility with v0.4.0 of python-bitcoinlib.

* Where appropriate, `RPC_INVALID_ADDRESS_OR_KEY` errors are now caught
  properly, which means that rather than raising `IndexError`, RPC commands
  such as `getblock` may raise `JSONRPCError` instead. For instance during
  initial startup previously python-bitcoinlib would incorrectly raise
  `IndexError` rather than letting the callee know that RPC was unusable. Along
  those lines, `JSONRPCError` subclasses have been added for some (but not
  all!) of the types of RPC errors Bitcoin Core returns.

Bugfixes:

* Fixed a spurious `AttributeError` when `bitcoin.rpc.Proxy()` fails.


## v0.6.1

New features:

* getblockheader RPC call now supports the verbose option; there's no other way
  to get the block height, among other things, from the RPC interface.
* subtoaddress and sendmany RPC calls now support comment and
  subtractfeefromamount arguments.


## v0.6.0

Breaking API changes:

* RPC over SSL support removed to match Bitcoin Core's removal of RPC SSL
  support in v0.12.0 If you need this, use an alternative such as a stunnel or
  a SSH tunnel.

* Removed SCRIPT_VERIFY constants ``bitcoin.core.script``, leaving just the
  constants in ``bitcoin.core.scripteval``; being singletons the redundant
  constants were broken anyway.

* SCRIPT_VERIFY_EVEN_S renamed to SCRIPT_VERIFY_LOW_S to match Bitcoin Core's naming

* SCRIPT_VERIFY_NOCACHE removed as Bitcoin Core no longer has it (and we never
  did anything with it anyway)


## v0.5.1

Various small bugfixes; see git history.

New features:

* New RPC calls: fundrawtransaction, generate, getblockheader
* OP_CHECKLOCKTIMEVERIFY opcode constant


## v0.5.0

Major fix: Fixed OpenSSL related crashes on OSX and Arch Linux. Big thanks to
everyone who helped fix this!

Breaking API changes:

* Proxy no longer has ``__getattr__`` to support arbitrary methods. Use
  RawProxy or Proxy.call instead. This allows new wrappers to be added safely.
  See docstrings for details.

New features:

* New RPC calls: getbestblockhash, getblockcount, getmininginfo
* Signing and verification of Bitcoin Core compatible messages. (w/ pubkey recovery)
* Tox tests
* Sphinx docs

Notable bugfixes:

* getinfo() now works where disablewallet=1


## v0.4.0

Major fix: OpenSSL 1.0.1k rejects non-canonical DER signatures, which Bitcoin
Core does not, so we now canonicalize signatures prior to passing them to
OpenSSL. Secondly we now only generate low-S DER signatures as per BIP62.

API changes that might break compatibility with existing code:

* MAX_MONEY is now a core chain parameter
* MainParams now inherits from CoreMainParams rather than CoreChainParams
* str(<COutPoint>) now returns hash:n format; previously was same as repr()
* RawProxy() no longer has _connection parameter

Notable bugfixes:

* MsgSerializable.to_bytes() no longer clobbers testnet params
* HTTPS RPC connections now use port 443 as default
* No longer assumes bitcoin.conf specifes rpcuser

New features:

* New RPC calls: dumpprivkey, importaddress
* Added P2P support for msg_notfound and msg_reject
* Added support for IPv6 addr messages


## v0.3.0

Major change: cleaned up what symbols are exported by modules. \_\_all\_\_ is now
used extensively, which may break some applications that were not importing the
right modules. Along those lines some implementation details like the ssl
attribute of the bitcoin.core.key module, and the entire bitcoin.core.bignum
module, are no longer part of the public API. This should not affect too many
users, but it will break some code.

Other notable changes:

* New getreceivedbyaddress RPC call.
* Fixed getbalance RPC call when wallet is configured off.
* Various code cleanups and minor bug fixes.


## v0.2.1

* Improve bitcoin address handling. P2SH and P2PKH addresses now get their own
  classes - P2SHBitcoinAddress and P2PKHBitcoinAddress respectively - and P2PKH
  can now convert scriptPubKeys containing non-canonical pushes as well as bare
  checksig to addresses.
* .deserialize() methods now fail if there is extra data left over.
* Various other small bugfixes.
* License is now LGPL v3 or later.


## v0.2.0

Major change: CTransaction, CBlock, etc. now come in immutable (default) and
mutable forms. In most cases mutable and immutable can be used interchangeably;
when that is not possible methods are provided to create new (im)mutable
objects from (im)mutable ones efficiently.

Other changes:

* New BIP70 payment protocol example. (Derren Desouza)
* Rework of message serialization. Note that this may not represent the final
  form of P2P support, which is still in flux. (Florian Schmaus)
* Various bugfixes

Finally starting this release, git tags will be of the form
'python-bitcoinlib-(version)', replacing the less specific '(version)' form
previously used.

