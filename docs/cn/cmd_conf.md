# 配置

## chain

查看当前 peth 连接的链。大部分链相关的命令均会使用此设置。
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

`Supported chains` 展示的是支持的链名称。使用 `chain <name>` 切换到新的链。
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

查看及修改当前的 sender 地址。`call` 命令会使用这里设置的值作为 `eth_call` 的默认 from 地址。
```
peth > sender
Current: 0x0000000000000000000000000000000000000000
peth > sender 0x0000000000000000000000000000000000000001
Current: 0x0000000000000000000000000000000000000000
New:     0x0000000000000000000000000000000000000001
```

## signer 

查看及修改当前的 signer。注意这里需要使用 private key 进行设置。`send` 命令会使用这里设置的值作为交易的默认 `from` 地址。

```
peth > signer
Current: Not set.
peth > signer 0x0000000000000000000000000000000000000000000000000000000000000001
Current: Not set.
New: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

## config

查看当前配置
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

修改配置

```
peth > config misc scan_api_interval 1
peth > config
...
scan_api_interval = 1
...
```