# Web3

## rpc_call

Initiate RPC calls. The supported methods can be referred to in the [Ethereum Json RPC documentation](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_protocolversion) and [Geth RPC documentation](https://geth.ethereum.org/docs/interacting-with-geth/rpc)

```
peth > rpc_call eth_getBalance 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 latest
"0x27a578953ce8145c92641"

peth > rpc_call eth_chainId
"0x1"

peth > rpc_call eth_blockNumber
"0x129cee9"

peth > rpc_call web3_clientVersion
"erigon/2.59.0/linux-amd64/go1.21.6"

peth > rpc_call eth_gasPrice
"0x3c432256c"

peth > rpc_call txpool_status
{
  "pending": "0x389aa",
  "queued": "0xde1"
}
```

## call

Initiate contract calls through `eth_call`. The function signature is used in the following form:
```
<method name>(<arg type>,<arg type>, ...)->(<return type>,<return type>, ...)
```

```
peth > call 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 symbol()->(string)
WETH

peth > call 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 balanceOf(address)->(uint) 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
748101950687662255047
```

## eth_call

Initiate `eth_call` using the original binary calldata

```
peth > abi_encode balanceOf(address)->(uint) 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
0x70a08231000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

peth > eth_call 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 0x70a08231000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
returns:
0x0000000000000000000000000000000000000000000000288e00088952e72bc7
```

## estimate_gas

Estimate the gas usage of transaction.

```
peth > estimate_gas 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 0x70a08231000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
gas:
23966
```

## address

Print address information including balance, nonce and code size.
```
peth > address 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
Balance: 2996232794632355541811083 Wei( 2996232.7946 Ether)
Nonce: 1
Code Size: 3124
```

## storage

View the contract storage data
```
peth > storage 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
0x0 : 0x577261707065642045746865720000000000000000000000000000000000001a
0x1 : 0x5745544800000000000000000000000000000000000000000000000000000008
0x2 : 0x0000000000000000000000000000000000000000000000000000000000000012
0x3 : 0x0000000000000000000000000000000000000000000000000000000000000000
...

peth > storage 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 1
0x1 : 0x5745544800000000000000000000000000000000000000000000000000000008
```

## status

Monitor the block producing and print gas information.

```
peth > status
2024-03-26 15:52:07.190743
        latest - Block 19517246, 167 txns, gas 162235/21000/2000000, 46.06% used rate, price 21/19/47 gwei
        pending - Block 19517247, 97 txns, gas 130751/21000/891576, 19.22% used rate, price 23/19/85 gwei
        pending - Block 19517247, 97 txns, gas 130751/21000/891576, 19.22% used rate, price 23/19/85 gwei
        pending - Block 19517247, 157 txns, gas 132415/21000/891576, 32.49% used rate, price 22/19/85 gwei
        pending - Block 19517247, 157 txns, gas 132415/21000/891576, 32.49% used rate, price 22/19/85 gwei
2024-03-26 15:52:14.316545
        latest - Block 19517247, 200 txns, gas 148473/21000/891576, 50.37% used rate, price 23/19/123 gwei
        pending - Block 19517248, 66 txns, gas 338304/21000/1786064, 14.93% used rate, price 20/19/22 gwei
        pending - Block 19517248, 66 txns, gas 338304/21000/1786064, 14.93% used rate, price 20/19/22 gwei
        pending - Block 19517248, 138 txns, gas 269707/21000/4381659, 42.65% used rate, price 20/19/23 gwei
        pending - Block 19517248, 138 txns, gas 269707/21000/4381659, 42.65% used rate, price 20/19/23 gwei
        pending - Block 19517248, 164 txns, gas 248094/21000/4381659, 50.50% used rate, price 20/19/31 gwei
....
```

## send_tx

Send transactions. TAKE CARE! It may lead fund loss as you are performing real blockchain interaction.

In the following case, we use a test environment for a demo.

Start a local evm chain.
```
$ ganache-cli
ganache v7.8.0 (@ganache/cli: 0.9.0, @ganache/core: 0.9.0)
Starting RPC server

Available Accounts
==================
(0) 0x36dD31837e6DF2717af500eccb0D3966541486A6 (1000 ETH)
(1) 0x0Cfcb5a6B7a2c917D1e1BF0A23e627Bd8aC13cb7 (1000 ETH)
....

Private Keys
==================
(0) 0x267bb9b0ca46b453c6185d7a50f7481978a2fe8dac7dd3f49dacd1d7e25f5897
(1) 0xdc8be184684b6c2f8b9853b638b3efb15d00634742f91465c7bae9eed58f81ec
....
```

Use peth to send transactions. 

1. Switch to the local chain
```
peth > chain local
Current:
  Chain: eth
     Chain ID: 1
     Block number: 19517329
  RPC: https://rpc.ankr.com/eth
  API: https://api.etherscan.io/api?apikey=TDMPDZU8RD4V9FVB66P5S47QETEJ6R61UY&
  Address: https://etherscan.io/address/
Changed:
  Chain: local
     Chain ID: 1337
     Block number: 0
  RPC: http://127.0.0.1:8545
  API: https://api.etherscan.io/api?
  Address: https://etherscan.io/address/
```

2. Set the signer private key.
```
peth > signer 0x267bb9b0ca46b453c6185d7a50f7481978a2fe8dac7dd3f49dacd1d7e25f5897
Current: Not set.
New:     0x36dD31837e6DF2717af500eccb0D3966541486A6
```

3. Send the transaction. Peth will keep waiting until getting the receipt.
```
peth > send_tx 0x0000 0x36dD31837e6DF2717af500eccb0D3966541486A6 100000
TX info:
  from :         0x36dD31837e6DF2717af500eccb0D3966541486A6
  to :   0x36dD31837e6DF2717af500eccb0D3966541486A6
  value :        100000
  chainId :      1337
  nonce :        0
  gas :  25200
  gasPrice :     2400000000
Sig info:
  Hash:  0xb151c07780e848d7b4459aba28dda6bc0a0040fa3efc34a9f93e0217b14856f6
  Raw Transaction:       0xf86880848f0d18008262709436dd31837e6df2717af500eccb0d3966541486a6830186a080820a96a0755a6fceed81c3eba86f7f43fc8a1c9e238150229bf97f625cb0c10d5296fa5fa06fad02abee3088ea341c73cda46af1bc08a0057b9af09026fde8f10ecf6d87af
  r:     53080391192678124694542854255230213858293389325864476756251831706085219564127
  s:     50512409173677094747841923700433357480448116896786676839214343048172512577455
  v:     2710
RPC: http://127.0.0.1:8545
Enter YES to send:YES
Sent 0xb151c07780e848d7b4459aba28dda6bc0a0040fa3efc34a9f93e0217b14856f6. Current block 0
New block 1
From: 0x36dD31837e6DF2717af500eccb0D3966541486A6
To: 0x36dD31837e6DF2717af500eccb0D3966541486A6
No signature found for selector 0x.
Full Receipt:
  transactionHash :      0xb151c07780e848d7b4459aba28dda6bc0a0040fa3efc34a9f93e0217b14856f6
  transactionIndex :     0
  blockNumber :  1
  blockHash :    0x6096bc1880226b4c91891a8a5974218f700e111215e0d111ce1c82cd503ce734
  from :         0x36dD31837e6DF2717af500eccb0D3966541486A6
  to :   0x36dD31837e6DF2717af500eccb0D3966541486A6
  cumulativeGasUsed :    21000
  gasUsed :      21000
  contractAddress :      None
  logs :         []
  logsBloom :    0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  status :       1
  effectiveGasPrice :    2400000000
  type :         0x0
```

## log

Search event logs. Search backward from the latest block, you can specify the search step and the number of loops.

```
peth >  log 0xdAC17F958D2ee523a2206206994597C13D831ec7 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef 1 1
Search start
 - log 1 blocks * 1 times
 - address 0xdAC17F958D2ee523a2206206994597C13D831ec7
 - topics 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef:
txid 0x783f09d45c738ddc7b78b5081ea29fdbbf38cb0c99da79e9b4a5bbc160ef7ca8
         address 0xdAC17F958D2ee523a2206206994597C13D831ec7
         topic[0] 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
         topic[1] 0x00000000000000000000000075e89d5979e4f6fba9f97c104c2f0afb3f1dcb88
         topic[2] 0x000000000000000000000000612791ab70cb156f1e0cb59d430fdeff99fa94d5
         data 0x0000000000000000000000000000000000000000000000000000000009e35861
txid 0x37948f1613eae871e19c7058d70cccef16780cf6d71749adcf6004b2f54a565a
         address 0xdAC17F958D2ee523a2206206994597C13D831ec7
         topic[0] 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
         topic[1] 0x000000000000000000000000f544aec5fc048df2a4c1e03c186b0c1e1675a519
         topic[2] 0x000000000000000000000000c7bbec68d12a0d1830360f8ec58fa599ba1b0e9b
         data 0x000000000000000000000000000000000000000000000000000000003b9aca00
...
```

## run

Execute Solidity code. The `Executor` contract and `run()` method need to be implemented in the file. The return value type of `run()` is not restricted. This command will compile and execute the corresponding solidity file. This method can be used when performing complex on-chain data queries and calculating logics.

```
peth > ! cat ethcall_executor.sol
pragma solidity ^0.8.13;
interface ERC20{
    function balanceOf(address a) external returns (uint);
}
contract Executor {
    function run() external returns(uint){
        return ERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7).balanceOf(0x5754284f345afc66a98fbB0a0Afe71e0F007B949);
    }
}

peth > run ethcall_executor.sol
993515703046496

peth > call 0xdAC17F958D2ee523a2206206994597C13D831ec7 balanceOf(address)->(uint256) 0x5754284f345afc66a98fbB0a0Afe71e0F007B949
993515703046496
```