# 交易

## tx

查看交易详情，并打印解码后的数据

```
peth > tx 0xa50588329b3b823f475e174399b21c66e04b3853c534496de58b46d06e8a432c
From: 0x9b782Dd6355530aba172B0Cb83425EBF7E6dECB0
To: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
Method: function transfer(address to, uint256 value) returns (bool )
Arguments:
     to : 0x468b64f1928208cc2c49b61f34fe515f4ddc59fa
     value : 250000000
ERC20 Transfers:
  USDC(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) sender->0x468B64f1928208CC2c49b61f34fE515f4ddC59FA 250000000
```

## tx_raw

打印原始的 Transaction 数据与 Receipt 数据

```
peth > tx_raw 0xa50588329b3b823f475e174399b21c66e04b3853c534496de58b46d06e8a432c
Transaction:
  blockHash :    0x3ae23a5c12918eed6bc2ff624b02ba71342532526cc9dad0ac1e6ba2627ef035
  blockNumber :  19517571
  from :         0x9b782Dd6355530aba172B0Cb83425EBF7E6dECB0
  gas :  68637
  gasPrice :     22585635097
  maxFeePerGas :         31080637298
  maxPriorityFeePerGas :         35858860
  hash :         0xa50588329b3b823f475e174399b21c66e04b3853c534496de58b46d06e8a432c
  input :        0xa9059cbb000000000000000000000000468b64f1928208cc2c49b61f34fe515f4ddc59fa000000000000000000000000000000000000000000000000000000000ee6b280
  nonce :        5
  to :   0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
  transactionIndex :     135
  value :        0
  type :         0x2
  accessList :   []
  chainId :      0x1
  v :    0
  r :    0xb22ac193fbf43fb6e4ce973e02490ccbd84c7bbb928070c4df4457365c6121b2
  s :    0x522b8c6e1edd212478472d5dad2ac41572701be383c715a555f6336aa651ec9d
  yParity :      0x0
Receipt:
  blockHash :    0x3ae23a5c12918eed6bc2ff624b02ba71342532526cc9dad0ac1e6ba2627ef035
  blockNumber :  19517571
  contractAddress :      None
  cumulativeGasUsed :    8926350
  effectiveGasPrice :    22585635097
  from :         0x9b782Dd6355530aba172B0Cb83425EBF7E6dECB0
  gasUsed :      40360
  logs :         [AttributeDict({'address': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'topics': [HexBytes('0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'), HexBytes('0x0000000000000000000000009b782dd6355530aba172b0cb83425ebf7e6decb0'), HexBytes('0x000000000000000000000000468b64f1928208cc2c49b61f34fe515f4ddc59fa')], 'data': '0x000000000000000000000000000000000000000000000000000000000ee6b280', 'blockNumber': 19517571, 'transactionHash': HexBytes('0xa50588329b3b823f475e174399b21c66e04b3853c534496de58b46d06e8a432c'), 'transactionIndex': 135, 'blockHash': HexBytes('0x3ae23a5c12918eed6bc2ff624b02ba71342532526cc9dad0ac1e6ba2627ef035'), 'logIndex': 194, 'removed': False})]
  logsBloom :    0x00000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000008000008000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000010000000000000004000010000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000
  status :       1
  to :   0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
  transactionHash :      0xa50588329b3b823f475e174399b21c66e04b3853c534496de58b46d06e8a432c
  transactionIndex :     135
  type :         0x2
```

## txs

打印某个地址相关的多条交易。

```
peth > txs 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
---- [1] 0xe7e0fe390354509cd08c9a0168536938600ddc552b3f7cb96030ebef62e75895 6082465 ----
0x95ba4cf87d6723ad9c0db21737d862be80e93911 creates contract FiatTokenV2_1(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48)
---- [2] 0xf73f2dd1e79552c5e13e92b16ed0a3a59b9e28fd134d6759a4e8cfbf3385a3c6 6082473 ----
0x95ba4cf87d6723ad9c0db21737d862be80e93911 -> FiatTokenV2_1(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48) value 0
Method: function changeAdmin(address arg0) returns ()
Arguments:
     arg0 : 0x69005ff70072c57547dc44ea975d85ea60e5b196
---- [3] 0xe152b8a0d9e83ddaa0158d7ca9beb0636d66e53e9498e5deb5a25aa3a324fba7 6082473 ----
0x95ba4cf87d6723ad9c0db21737d862be80e93911 -> FiatTokenV2_1(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48) value 0
Method: function initialize(string tokenName, string tokenSymbol, string tokenCurrency, uint8 tokenDecimals, address newMasterMinter, address newPauser, address newBlacklister, address newOwner) returns ()
Arguments:
     tokenName : USD//C
     tokenSymbol : USDC
     tokenCurrency : USD
     tokenDecimals : 6
     newMasterMinter : 0x1500a138523709ce66c8b9abe678abc1b6c5a7b7
     newPauser : 0xe8e13e1b6d363c270ef3a5ab466ebad8326311bb
     newBlacklister : 0x063d13783a0a2ce65b1ca00d9e897e6c8b1ec86b
     newOwner : 0xa61e278899a8553d93d14eb19ba2791e05069e87
     ...
```

打印最新的几个交易

```
peth > txs 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 2 desc
---- [1] 0x9ee4118fb5e17fc31f3f29c6584e34c25e36e5ada5ad00b17fbc7d0fcccd8e67 19517675 ----
0xe655b02a6ceba30e45567fa903685fe867cd3120 -> FiatTokenV2_1(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48) value 0
Method: function transfer(address to, uint256 value) returns (bool )
Arguments:
     to : 0x7b3fe4ee762c37fd98f5519f097537ced8a142c5
     value : 750000000
---- [2] 0xddf2682a313de0a0ff4d757d6fdae6a22b26dbd37290a30a52127ab5a69c2d69 19517675 ----
0x28c6c06298d514db089934071355e5743bf21d60 -> FiatTokenV2_1(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48) value 0
Method: function transfer(address to, uint256 value) returns (bool )
Arguments:
     to : 0x37360d8142eec051d9bb31d5ebd6fab02d658c9b
     value : 1053934201
```