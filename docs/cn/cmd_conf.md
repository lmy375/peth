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

修改 peth 中的一些默认设置
```
peth > config
SIG_DB_PATH = '....'
...
SCAN_API_INTERVAL = 6
DIFF_MIN_SIMILARITY = 0.5
ENABLE_SLITHER = False

Use `config key value` to change settings.
peth > config SCAN_API_INTERVAL 1
peth > config
...
SCAN_API_INTERVAL = 1
...
```