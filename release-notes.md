# python-bitcointx release notes
## v1.1.2

Breaking changes:

    BIP32PathTemplate now uses '{' and '}' for index ranges rather than '[' and ']'
    While this is a seriously breaking change, the BIP32 template feature is not widely used,
    and the finalized BIP88 uses curly brackets instead of square brackets.

Non-breaking changes:

    Make PartiallySignedTransaction a dispatched class, mapped to PartiallySignedBitcoinTransaction

    ECDSA signing code now grinds for Low-R by default (same as Core does)

    Do not accept uncompressed pubkeys by default in `from_pubkey()` method for single-key address
    classes, and in `standard_multisig_redeem_script()`

    RPCCaller config-reading code takes 'chain=' config option into account for 'network_id',
    thus, for example, with 'chain=liquidregtest', it will look for 'liquidregtest.rpcport'
    before bare 'rpcport' option


## v1.1.1.post2

Fix a useability problem in `PartiallySignedTransaction` where `PSBT_Input`s that did not have
an utxo assigned prevented the use of `psbt.sign()` to sign all other inputs on PSBT, because
ValueError were raised on calling `sign()` of this input.

Now `None` is returned in this case (and also if `index` is not set on `PSBT_Input`), and
an exception is not raised. If you need to know if all psbt inputs are 'signable', you can
just iterate over PSBT inputs and call `inp.sign(...)` directly and check if None is returned.
If there's no key in `KeyStore` passed to `sign()`, `PSBT_InputSignInfo` will be returned with
`num_new_sigs=0`, so when None is returned it means there's no way to sign the input with
current data present in it, even if we knew the key.

## v1.1.1.post1

Fix bug introduced in v1.1.1.post0: `set_utxo(None, ...)`, has unexpectedly changed
semantics - instead of clearing the utxo, it used the utxo already-stored in the input.
Such sudden change of semantics should not happen, but regretfully it slipped through.

Add new `is_final()` methods to `PartiallySignedTransaction` and `PSBT_Input`

## v1.1.1.post0

Allow the PSBT to have both `NON_WITNESS_UTXO` and `WITNESS_UTXO` for the same
input on deserialization, as current redaction of BIP174 allows this. The fields
will be checked to be in-sync (that witness utxo is included in "non-witness"
full-transaction UTXO at the right position)

On PSBT serialization, if `PSBT_Input` has both CTransaction as `utxo` property
and non-Null `witness_utxo` property, both `NON_WITNESS_UTXO` and `WITNESS_UTXO`
will be present in the serialization of this input, unless `always_include_witness_utxo=False`
was passed to `deserialize()`.

To force the `witness_utxo` field of `PSBT_Input` to be populated even though
the "witness-ness" cannot be inferred from the supplied `CTransaction`, the
`force_witness_utxo=True` kwarg (default is False) can be supplied to
`PSBT_Input.__init__()` and `set_utxo()` methods of `PSBT_Input` and
`PartiallySignedTransaction`.


## v1.1.1

Do not set error callback in secp256k1 - the default handler will do abort()
with an error message. There is no safe continuation possible after this happens,
and this situation should never happen. The python handler would need to do
os.abort() anyway.

Fixes for openssl loading (only relevant for historical signatures:
    - Fix issue with libssl on MacOSX 10.15. by trying to load `libssl.35` first
    - The `libeay32` library is only tried to be loaded on Windows platform

Tests for PyPy are removed. The compatibilty of ctypes module in PyPy with ctypes
in CPython is lacking, and debugging the quirks of PyPy implementation is too costly,
given that the code that looks good and runs perfectly with CPython fails on PyPy with
incomprehensive messages. Use PyPy at your own risk, there will likely be bugs around
ctypes interaction.

## v1.1.0

Breaking changes:

    PSBT: allow full CTransaction to be stored in `PSBT_Input` for segwit inputs.
    This will allows protection workaround for potential large-fee-ransom attacks
    against autonomous singners of segwit transactions
    (details: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-August/014843.html
     and https://twitter.com/FreedomIsntSafe/status/1268572922911887360)

    `PSBT_Input.utxo` field cannot be set directly anymore, only via
    `input.set_utxo(utxo, unsigned_tx)` method, that takes `unsigned_tx` as parameter.
    It will automatically set `witness_utxo` field of the input. The value of
    `witness_utxo` field will depend on other fields of the input, and the supplied
    `unsigned_tx` (which can be None)
    There's also `psbt.set_utxo(utxo, index)`, which is equivalent to
    `psbt.inputs[index].set_utxo(utxo, psbt.unsigned_tx)`

    Checking `isinstance(inp.utxo, CTxOut)` becomes unreliable, because it can be segwit
    input, but still contain `CTransaction`. `inp.witness_utxo` should be checked instead.
    It will be None for non-segwit input, and `CTxOut` instance for segwit input.
    Conversely, `inp.non_witness_utxo` It will be None for segwit input,
    and `CTransaction` instance for non-segwit input.

    More strict BIP32Template parser: no whitespace allowed, no leading zeroes in indexes

Non-breaking changes:

    Add `set_custom_secp256k1_path()` to set custom path to load secp256k1
    library, and `get_custom_secp256k1_path()` to get the path set earlier.
    For `set_custom_secp256k1_path()` to have any effect, it has to be called
    before importing any other modules except `bitcointx` and `bitcointx.util`

    Openssl library is now only attempted to be imported if
    `CPubKey.verify_nonstrict()` is called, and not on import of `core.key`.
    Also, `set_custom_openssl_path()`, `set_custom_openssl_path()` are added,
    analogous to the ones for secp256k1

    `load_secp256k1_library()` from `bitcointx.core.secp256k1` now accepts
    explicit path, `load_secp256k1_library(path='/path/to/library')`

    `load_bitcoinconsensus_library()`
    from `bitcointx.core.bitcoinconsensus` now accepts explicit path,
    `load_bitcoinconsensus_library(path='/path/to/library')`

    Typing change: pubkeys list for `standard_multisig_redeem_script` is now
    `List[CPubKey]`. Previously it was `List[Union[CPubKey, bytes, bytearray]]`,
    but it was less safe. This is only typing, though -- the function does
    not validate the pubkeys nor checks the types at runtime.

    New convenience methods for `PartiallySignedTransaction`: `get_output_amounts()`
    and `get_fee()`

## v1.0.5

* Fix CScriptWitness initialization: previously, it converted small ints
  to `OP_1`..`OP_16` opcodes, which is wrong: the witness should include
  data as-is (encoded with bn2vch), because this is not a script.
  But to allow to specify opcodes in the witness, `CScriptWitness.__init__`
  now checks if the item is an instance of `CScriptOp`,
  and if it is, places a one-byte opcode in the witness.

  Note that this might be a breaking change, because `CScriptWitness([1])`
  previously gave `[x('51')]`, and now it gives `[x(01)]`.
  Previous behavior was incorrect, and would lead to script execution
  failures due to incorrect witnesses, which would be quickly noticed in
  develpment. No github issues were raised related to this problem.
  python-bitcoinlib did not allow to specify `int`s in a CScriptWitness,
  so legacy code is not affected.

* Additional sanity checks for PSBT: check that input and output amounts
  and prevout indexes are always in valid range

* Do not raise ValueError when signing PSBTs where some inputs contain
  p2sh scriptPubKeys without specified redeem scripts.
  This is 'cannot sign' situation rather than 'invalid structure', because
  there is legitimate situations where redeem scripts might not be known
  for some of the inputs at the time we want to sign other inputs.

## v1.0.4

Fixes and improvements in PSBT processing, use Decimal for coin values

Fixes:

* While finalizing p2sh-p2wpkh PSBT input, `final_script_sig` was not set
* Sanity checks for `PSBT_Output` incorrectly expected witness script to
  be present for p2wpkh/p2sh-p2wpkh outputs

Breaking changes:

* `satoshi_to_coins` now returns `decimal.Decimal` rather than `float`.
  This is to prevent rounding errors when CoreParams specify `MAX_MONEY` that
  is beyond the range that can be safely represented with `float` without loss
  of precision, or `satoshi_to_coins` is called with `check_range=False` with
  value outside MoneyRange.

Non-breaking changes:

* json encoding in `bitcointx.rpc` now hanles Decimal values while only standard
  json module is imported (`DecimalJSONEncoder` is added). The conversion
  routine in this class also checks that conversion did not result in precision
  loss up to 8 decimal points with `f'{r:.08f}' != f'{o:.08f}'` check, and
  raises TypeError if the check fails.
* PSBT deserialization code can now convert non-witness UTXO to witness UTXO
  if `allow_convert_to_witness_utxo=True` is passed to `deserialize()`
  (or `from_base64()`, `from_binary()`, `from_base64_or_binary()`)
* `KeyStore` got `replace_external_privkey_lookup()` and 
  `replace_external_pubkey_lookup()` methods to set key lookup callbacks on
  existing KeyStore instance. The methods return previous callback value.

## v1.0.3

Improvements related to PSBT and BIP32 paths handling.

This version introduces BIP32 path templates and makes `KeyStore` require
association of extended keys with these templates. Templates are the same as
BIP32 paths, but indexes can be specified as ranges (`[23-55]`) or wildcards
(`*`). For exmple, a template that allows BIP44,BIP49 and BIP84 paths with last
index going up to 50000, will look like `m/[44,49,84]'/0'/0'/[0-1]/[0-50000]`.

In v1.0.2, PSBT support was introduced along with `KeyStore` class that made
signing PSBT convenient, but checking that derivation paths specified in PSBT
are sane was not convenient. Now `KeyStore` by default requires that any extended
key have `BIP32PathTemplate` associated with it (but this can be bypassed via
`require_path_templates=False` argument). Default path template can be specified
at `KeyStore` creation with `default_path_template` argument (it can be a string
or `BIP32PathTemplate`). To specify individual path for certain extended key,
supply a tuple of `(key, <path_template>)` or `(key, [<tmpl1>, <tmpl2>, ...])`
to `KeyStore`. Please refer to `bitcointx/tests/test_keystore.py` and
`examples/sign-psbt.py` for usage examples.

Breaking changes:

* `KeyStore` now accepts extended keys only with specified path templates by default
  (as tuple `(xkey, BIP32PathTemplate)` or if `default_path_template` kwarg was
  specified at `KeyStore` creation. Pass `require_path_templates=False` for KeyStore
  to accept extended keys without path templates. When no path template is specified
  for extended key, KeyStore allows derivation for any paths supplied to
  `get_privkey()`/`get_pubkey()`. Otherwise the path must match one of the templates
  specified for extended keys. Note that non-extended keys always match their `key_id`.
* `KeyStore`'s `get_privkey()` and `get_pubkey()` second argument now
  is KeyDerivationInfo, not Dict[bytes, KeyDerivationInfo]. Using dict was a mistake,
  because we always need only one entry, the `key_id` one. If the caller has a dict,
  it can also look up the derivation info itself.
* Calling `KeyStore`'s `get_privkey()` and `get_pubkey()` without second argument
  specified will search only for non-extended keys. To get priv/pub of extended keys
  without derivation, `KeyDerivationInfo` with empty (`BIP32Path('')`
  or `BIP32Path('m')`) has to be specified.
* KeyDerivationInfo's `master_fingerprint` renamed to `master_fp`,
  and KeyDerivationInfo now does not store pubkeys. Derivation maps in `PSBT_Input`
  and `PSBT_Output` now map from `pubkey` to `PSBT_KeyDerivationInfo`
* BIP32Path handling became more strict, extended keys now can retain associated
  `derivation_info` through derivations, and it is checked if the path given to
  `derive_path(path)` is full path or partial path. It can only accept full path
  if the current key has depth = 0.

Non-breaking changes:

* `BIP32Path`: paths can now skip 'm/' at the beginning, and `BIP32Path` now has
  `is_partial()` method that returns False when if the path is not partal - starts
  from master, 'm/', or False if it is not starts from master. String representations
  also use this property and return results with 'm/' prefix or without.
* Typing fixes for issues revelead by mypy 0.760

## v1.0.2.post0

* fix PSBT outputs decode: `redeem_script` was set instead of `witness_script`

## v1.0.2

* Library is now fully type-annotated and statically checked using
  [mypy](https://github.com/python/mypy). The main code of the library and the examples
  are checked with --strict option, while the tests are checked with default settings.
* Added support for PSBT (BIP174 partially signed transactions). For usage examples,
  please refer to `bitcointx/tests/test_psbt.py`

* IMPORTANT FIX (with potential security implications):
  `parse_standard_multisig_redeem_script()` - a check was added that there are
  no extra unexpected opcodes. Before the fix, this function could incorrectly report
  certain non-standard multisig scripts as 'standard' and return pubkeys that might
  not be the pubkeys of the keys that control the actual spending.

  If you need to compare that some untrusted redeem script matches some known keys,
  the best and least error-prone approach is to construct the new redeem
  script using those known keys and then compare the final script with the untrusted one.

  If you instead chosen to use this function to parse untrusted data and then compare
  the extracted pubkeys with known ones, the function before the fix could allow
  to bypass such checks. It was not initially considered that this function would be used
  for parse-untrusted-data-then-compare-components tasks, but nothing is stopping
  anyone from using this function in this way, and therefore not checking that there is
  no unexpected extra opcodes can be considered a serious flaw, which was fixed
  in this release.

  Also, `parse_standard_multisig_redeem_script()` now raises ValueError if there are
  duplicate pubkeys found in the script.

Breaking changes:

* `parse_standard_multisig_redeem_script()` now returns an instance of
  `StandardMultisigScriptInfo` instead of a dict (typecheking with dicts that
  have heterogenous values is a pain)
* `bitcointx.core.scripteval.EvalScriptError` now does not directly store various
  script eval state variables. There is now `ScriptEvalState` class that stores those,
  and `EvalScriptError` has `state` attribute that stores the state as the instance
  of that class

Deprecations:

* `CPubKey.is_valid()` is deprecated due to possibility of confusion 
  with `CPubKey.is_fullyvalid()`. `CPubKey.is_valid()` will be removed
  in the future. Please use `CPubKey.is_nonempty()` instead.
  CPubKey's `is_valid()`/`is_fullyvalid()` was modelled after BitcoinCore's
  CPubKey's `IsValid()`/`IsFullyValid()`, but the possible confusion and
  subsequent incorrect checks is dangerous, and it is better to not maintain
  the correspondense with Core in this case.

Non-breaking changes:

* Added `standard_witness_v0_scriptpubkey()` -- a helper function that checks the length
  of supplied keyhash or scripthash, and then returns `CScript([0, keyhash_or_scripthash])`
* Removed `CScript.to_p2wpkh_scriptPubKey()` - it was incorrect, and the only thing that
  it can be used for, if implemented correctly, is to convert P2PKH to P2WPKH address,
  which is not very interesting thing to do, and can be done easily with
  `standard_witness_v0_scriptpubkey()`
* Added signet support `bitcoin/signet`.
* Return current chain params in ChainParams context manager.
* RPCCaller now looks for rpc user/password in chain-specific section in bitcoin.conf
  if it cannot find rpcpassword in global section, and can take config file contents
  as `conf_file_contents` named arg. Conf dir lookup for Bitcoin testnet is fixed
  (the network id is 'test', the extra data dir is 'testnet3')
* `select_chain_params` returns tuple of previous chain params and new chain params. 
* Some asserts in the library are conveted to the checks that raise
  `ValueError` or `TypeError` depending on the check.
* Fix class attribute dispatching code - ignore attributes of `abc.ABC` class
  when dispatching attribute access - otherwise isinstance/issubclass might
  give incorrect results due to `ABC._abc_cache` confusion
* Added checks for function or method argument types at runtime.
  `coins_to_satoshi()` will raise `TypeError`
  if the value is not an instance of int, float, or Decimal, for example.
* Fixes for minor bugs revealed by mypy after type declarations was added
* `CPubKey.recover_compact()` now returns None on failure to recover
  (it previously returned False, which is not consistent with the fact
  that it returns CPubKey on success)
* CBech32Data now has `bech32_witness_version` field instead of `witver`
* `bitcointx.core.serialize module`: `uint256_from_str` renamed to `uint256_from_bytes`,
  `uint256_to_str` renamed to `uint256_to_bytes`, for the name to reflect the
  actual returning type (`_str` suffix is likely a remnant of python2)
* Result types for `to_mutable()` / `to_immutable` methods are only provided
  for `CTransaction` and its subclasses. Classes for transaction components,
  such as `CTxOut` etc. still have `to_mutable()`/`to_immutable()` methods,
  but their return types will be Any. `CMutableTxOut.from_instance(immutable_txout)`
  will always have correct the result type, so you can use it instead.
* `scripteval.VerifyWitnessProgram()` returns None. It was returning True previously,
  in case of success, but in case of failure, it raised an exception. The result was
  never examined - so it was not correct to use bool as a return type.
* Threading is actually supported now, threading-related tests added
* Asyncio is supported for python >= 3.7
* sighash-calculation functions now has their `amount` argument as None by default
  (before it was 0). With `SIGVERSION_BASE`, amount is not used, and for
  `SIGVERSION_WITNESS_V0`, amount must be specified.
* `CTxWitness.stream_deserialize()` is now a classmethod, same as
  `stream_deserialize()` methods of all other classes. It expects to be
  supplied with `num_inputs=` keyword argument.
* fix `CScript.to_p2wsh_scriptPubKey()` -- check for 3600 bytes standardness
  limit instead of 520 byte limit that is applicable for p2sh, not for p2wsh
* `core.serialize.VarIntSerializer` now checks for value bounds of deserialized
  compact size integer. If it enconters non-canonical encoding, or the size
  bigger than `MAX_SIZE` (0x02000000) it throws DeserializationValueBoundsError

## v1.0.1

* fixed handling of flags in `VerifyScript()` and `ConsensusVerifyScript()`.
  `ConsensusVerifyScript()` only accepted flags as a set, which was
  incompatible with `VerifyScript()`, which also accepted flags as a tuple.

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
    integers. Has `from_int()` and `to_int()` methods.

* Classes representations for `repr()` and `str()` can significantly
  differ, with `repr()` giving more detailed view, and for example for
  confidential data in Elements blockchain, `str()` may show
  'CONFIDENTIAL', if the data cannot be meaningfully interpreted.
  `repr()` will show the data as-is.

* Misc
  - `CTransaction` default version changed to 2
  - if `bytes` is accepted by some method, `bytesarray` will be, too
  - core.script: `CHECKSEQUENCEVERIFY` added (no support in VerifyScript yet)
  - the byte before private data of extended private key must be zero.
    Bitcoin core ignores this, but the standard says that is should be zero.
    `CKeyBase.__init__()` will raise ValueError if it is not.
  - secp256k1 C library definitions moved to separate file
  - `bitcointx.core.sha256` module added - slow, python-only implementation
    of SHA256, but with useful property that it allows to get the SHA256
    mid-state. Needed for Elements, might be useful for other things.
  - CPubKey() can be instantiated without parameters
    (will return invalid pubkey instance)
  - utility functions and methods: to handle multisig scripts:
    `standard_multisig_redeem_script`, `standard_multisig_witness_stack`,
    `parse_standard_multisig_redeem_script`; to handle amounts:
    `coins_to_satoshi`, `satoshi_to_coins`; to calculate transaction
    virtual size: `tx.get_virtual_size()`
  - bugfix in VerifyWitnessProgram (part of VerifyScript) - it was breaking on
    p2wsh, and on integer values on witness stack
  - `de()serialize` and `stream_(de)serialize` now always work with `**kwargs`
    instead of additional params being passed as dict
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
    -  `CPubKey.recover_compact()` returns None on failure to recover, instead of False

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

