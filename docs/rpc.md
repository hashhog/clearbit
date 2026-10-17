# RPC reference

clearbit serves Bitcoin Core's JSON-RPC interface over HTTP on the RPC port (8332 mainnet, 48332 testnet4, 18332 testnet3, 18443 regtest). Methods, parameter order and result fields follow Bitcoin Core; a client written for `bitcoind` should work unchanged.

## Calling it

Authenticate with the cookie the node writes to `<datadir>/<network>/.cookie`, or with `--rpcuser` / `--rpcpassword`. Requests are JSON-RPC 1.0 or 2.0 objects, or a JSON array of them (batch). Wallet methods take the wallet from the URL path `/wallet/<name>`, as in Core; with exactly one wallet loaded the plain `/` path also works.

```bash
COOKIE="$(cat "$DATADIR/regtest/.cookie")"
curl -s --user "$COOKIE" -d '{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]}' http://127.0.0.1:18443/
curl -s --user "$COOKIE" -d '[{"method":"getblockcount"},{"method":"getbestblockhash"}]' http://127.0.0.1:18443/
curl -s --user "$COOKIE" -d '{"method":"help","params":["getblockhash"]}' http://127.0.0.1:18443/
```

`help` with no argument lists 125 methods. The dispatch table in `src/rpc.zig` (`handleSingleRequest`) has 139; the 14 extra ones are marked † below and answer normally. Several of them are also hidden from `help` in Core (`generate*`, `invalidateblock`, `reconsiderblock`, `addpeeraddress`).

## REST

A REST interface like Core's is always on at `/rest/` on the RPC port. It needs no authentication, so do not expose the RPC port beyond hosts you trust. Endpoints: `chaininfo.json`, `mempool/info.json`, `mempool/contents.json`, `block/<hash>`, `block/notxdetails/<hash>`, `tx/<txid>`, `headers/<count>/<hash>`, `blockhashbyheight/<height>`, `getutxos[/checkmempool]/<txid>-<n>/...`, `blockfilter/<type>/<hash>`, `blockfilterheaders/<type>/<count>/<hash>`, each with a `.bin`, `.hex` or `.json` suffix.

```bash
curl -s http://127.0.0.1:18443/rest/chaininfo.json
```

## Known differences from Core

- Error codes. Methods listed in Core's argument table return Core's `-1` "Wrong number of arguments" for a wrong argument count, but the methods outside it (most of those marked †) return `-32602` with clearbit's own message, and some type or range errors use different codes or wording from Core.
- `--rpc-tls-cert` / `--rpc-tls-key` cannot be used: Zig 0.13 has no TLS server, so the node refuses to start when both are set.
- Methods Core v31 no longer has (`dumpprivkey`, `importprivkey`, `sethdseed`) and methods Core never had (`getsyncstate`, `dumpmempool`, `loadmempool`, `getpayjoinrequest`, `sendpayjoinrequest`) are noted in the tables.
- The tables list only differences found by running both nodes; an empty cell means none is known, not that the method has been compared field by field.

## Blockchain

| Method | Known differences from Core |
|---|---|
| `dumpmempool` † | clearbit only: alias of `savemempool`. |
| `dumptxoutset` |  |
| `getbestblockhash` |  |
| `getblock` |  |
| `getblockchaininfo` |  |
| `getblockcount` |  |
| `getblockfilter` | |
| `getblockfrompeer` |  |
| `getblockhash` |  |
| `getblockheader` |  |
| `getblockstats` |  |
| `getchainstates` |  |
| `getchaintips` |  |
| `getchaintxstats` |  |
| `getdeploymentinfo` |  |
| `getdifficulty` |  |
| `getmempoolancestors` |  |
| `getmempooldescendants` |  |
| `getmempoolentry` |  |
| `getmempoolinfo` |  |
| `getorphantxs` |  |
| `getrawmempool` |  |
| `getsyncstate` † | clearbit only: tip and best-header heights and hashes. |
| `gettxout` |  |
| `gettxoutproof` |  |
| `gettxoutsetinfo` | Also returns a `hash_serialized_2` field holding the same value as `hash_serialized_3`; Core v31 has no such field. |
| `gettxspendingprevout` | |
| `importmempool` |  |
| `invalidateblock` † |  |
| `loadmempool` † | clearbit only: reloads `mempool.dat`. |
| `loadtxoutset` |  |
| `preciousblock` |  |
| `pruneblockchain` | |
| `reconsiderblock` † |  |
| `savemempool` |  |
| `scanblocks` |  |
| `scantxoutset` |  |
| `verifychain` |  |
| `verifytxoutproof` |  |
| `waitforblock` |  |
| `waitforblockheight` |  |
| `waitfornewblock` |  |

## Control

| Method | Known differences from Core |
|---|---|
| `getmemoryinfo` |  |
| `getrpcinfo` |  |
| `help` |  |
| `logging` |  |
| `stop` |  |
| `uptime` |  |

## Generating

| Method | Known differences from Core |
|---|---|
| `generateblock` † |  |
| `generatetoaddress` † |  |
| `generatetodescriptor` † |  |

## Mining

| Method | Known differences from Core |
|---|---|
| `getblocktemplate` |  |
| `getmininginfo` |  |
| `getnetworkhashps` |  |
| `getprioritisedtransactions` |  |
| `prioritisetransaction` |  |
| `submitblock` |  |
| `submitheader` |  |

## Network

| Method | Known differences from Core |
|---|---|
| `addnode` |  |
| `addpeeraddress` † |  |
| `clearbanned` |  |
| `disconnectnode` |  |
| `getaddednodeinfo` |  |
| `getaddrmaninfo` |  |
| `getconnectioncount` |  |
| `getnettotals` |  |
| `getnetworkinfo` |  |
| `getnodeaddresses` |  |
| `getpeerinfo` |  |
| `listbanned` |  |
| `ping` |  |
| `setban` |  |
| `setnetworkactive` |  |

## Rawtransactions

| Method | Known differences from Core |
|---|---|
| `analyzepsbt` |  |
| `combinepsbt` |  |
| `combinerawtransaction` |  |
| `converttopsbt` |  |
| `createpsbt` |  |
| `createrawtransaction` |  |
| `decodepsbt` |  |
| `decoderawtransaction` |  |
| `decodescript` |  |
| `descriptorprocesspsbt` |  |
| `finalizepsbt` |  |
| `fundrawtransaction` |  |
| `getrawtransaction` | |
| `joinpsbts` |  |
| `sendrawtransaction` |  |
| `signrawtransactionwithkey` |  |
| `submitpackage` |  |
| `testmempoolaccept` |  |
| `utxoupdatepsbt` |  |

## Util

| Method | Known differences from Core |
|---|---|
| `createmultisig` |  |
| `deriveaddresses` |  |
| `estimaterawfee` |  |
| `estimatesmartfee` |  |
| `getdescriptorinfo` |  |
| `getindexinfo` |  |
| `signmessagewithprivkey` |  |
| `validateaddress` |  |
| `verifymessage` |  |

## Wallet

| Method | Known differences from Core |
|---|---|
| `backupwallet` |  |
| `bumpfee` |  |
| `createwallet` |  |
| `dumpprivkey` † | Removed from Core with the legacy wallet; kept here. |
| `encryptwallet` |  |
| `getaddressinfo` |  |
| `getbalance` |  |
| `getbalances` |  |
| `getnewaddress` |  |
| `getpayjoinrequest` † | clearbit only: BIP-78 PayJoin receiver (`--payjoin-server-url`). |
| `gettransaction` |  |
| `getwalletinfo` |  |
| `importdescriptors` |  |
| `importprivkey` † | Removed from Core with the legacy wallet; kept here. |
| `listdescriptors` |  |
| `listlockunspent` |  |
| `listtransactions` |  |
| `listunspent` |  |
| `listwalletdir` |  |
| `listwallets` |  |
| `loadwallet` |  |
| `lockunspent` |  |
| `psbtbumpfee` |  |
| `rescanblockchain` |  |
| `restorewallet` |  |
| `send` |  |
| `sendpayjoinrequest` † | clearbit only: BIP-78 PayJoin sender, plain HTTP only. |
| `sendtoaddress` |  |
| `sethdseed` † | Removed from Core with the legacy wallet; takes a 16 to 64-byte hex seed. |
| `setlabel` |  |
| `signmessage` |  |
| `signrawtransactionwithwallet` |  |
| `unloadwallet` |  |
| `walletcreatefundedpsbt` |  |
| `walletlock` |  |
| `walletpassphrase` |  |
| `walletpassphrasechange` |  |
| `walletprocesspsbt` |  |
