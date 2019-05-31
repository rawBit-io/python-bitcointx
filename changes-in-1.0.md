Frontend classes

Chain params:
    - new function names
    - contexts
    - thread-local
    - new specialization params (`TRANSACTION_CLASS` etc)
    - new naming (bitcoin, bitcoin/testnet ...)
    - CurrentChainParams()

AddressEncodingError - more general, includes Base58Error and Bech32Error

core frontend class conventions

wallet: address frontend class conventions, CoinAddress, etc
CoinKey(), CoinExtKey()

script frontend class conventions

rpc: RPCCaller - the same as RawProxy. Proxy is removed

`CBech32Data.from_bytes` - changed arg order, witver is now kwarg

repr/str distinction

Uint256 class

`is_valid` -> `is_valid()` etc. (list them: valid, fullyvalid, compressed,...),
`@no_bool_use_as_property`, correctness over speed


CTransaction default version changed to 2

`to_mutable()`/`to_immutable()`

BIP32Path(), `CExtKeyBase.derive_path()`

bytesarray accepted where bytes accepted

core.key.ECDH

CKey, CPubkey combine(), add(), sub(), negated()

check that first byte of xprivkey is zero (Bitcoin core ignores this, we are not)

core.script: add CHECKSEQUENCEVERIFY (no processing though)
add `DATA()`, `NUMBER()`, `OPCODE()`

CScript: add `to_p2wsh_scriptPubKey()`, add `sighash()`

tx.serialize: add `for_sighash` flag

move secp256k1 into separate file

core.sha256 for midstate calc

