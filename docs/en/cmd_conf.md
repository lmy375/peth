# Configuration

## chain

Check the chain currently connected to peth. Most chain-related commands depend on this setting.

```
peth > chain
Current:
  Chain: eth
     Chain ID: 1
     Block number: 19515936
  RPC: https://rpc.ankr.com/eth
  API: https://api.etherscan.io/api?
  Address: https://etherscan.io/address/
Supported chains: local, eth, ethw, etf, bsc, heco, matic, avax, ftm, metis, arb, boba, one, cro, oasis, aoa, moonriver, moonbeam, op, gnosis, canto, zksync, zkfair, base, mantle, manta, merlin, blast
```

`Supported chains` shows the names of supported chains. Use `chain <name>` to switch to a new chain.

```
peth > chain bsc
Current:
  Chain: eth
     Chain ID: 1
     Block number: 19515937
  RPC: https://rpc.ankr.com/eth
  API: https://api.etherscan.io/api?
  Address: https://etherscan.io/address/
Changed:
  Chain: bsc
     Chain ID: 56
     Block number: 37295652
  RPC: https://rpc.ankr.com/bsc
  API: https://api.bscscan.com/api?
  Address: https://bscscan.com/address/
```

## sender

View and modify the current sender address which will be used by the `call` and `eth_call` command.

```
peth > sender
Current: 0x0000000000000000000000000000000000000000
peth > sender 0x0000000000000000000000000000000000000001
Current: 0x0000000000000000000000000000000000000000
New:     0x0000000000000000000000000000000000000001
```

## signer 

View and modify the current signer. Note that you need to set this with a private key. 

The `send` command will use the value set here as the default `from` address for transactions.

```
peth > signer
Current: Not set.
peth > signer 0x0000000000000000000000000000000000000000000000000000000000000001
Current: Not set.
New: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

## config

Print current settings.
```
peth > config
root = ..
chains_path = ..
...
scan_api_interval = 6
sig_db_url = https://raw.githubusercontent.com/ethereum/go-ethereum/master/signer/fourbyte/4byte.json
diff_min_similarity = 0.5
enable_slither = False

peth > config raw
[path]
root = peth-data

[root]
chains = chains.yaml
tokens = tokens.yaml
contracts = contracts.yaml
sig_db = 4byte.json
output = output
cache = cache

[output]
diff = diff
report = report
sources = sources

[cache]
evm = evm
contracts = contracts

[misc]
scan_api_interval = 6
sig_db_url = https://raw.githubusercontent.com/ethereum/go-ethereum/master/signer/fourbyte/4byte.json
diff_min_similarity = 0.5
enable_slither = false
```

Modify settings.
```
peth > config misc scan_api_interval 1
peth > config
...
scan_api_interval = 1
...
```