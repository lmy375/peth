# peth-cli

A python Ethereum utilities command-line tool.

After wasting the all day trying to install [seth](https://github.com/dapphub/dapptools/tree/master/src/seth) and failed, I took another day to write this. :(

Ugly code but works :)

Wish the ~~meta~~ universe ~~peth~~ peace !

# Usage

## [Optional] Use your own config.json. 

```
{
    "eth": [ // Network name
        "https://rpc.ankr.com/eth",      // RPC endpoint URL.
        "https://api.etherscan.io/api?"  // Etherscan-style API URL.

    // Get better experience if you have an API key.
    // https://api.etherscan.io/api?apikey=<Your API Key>&
    
    // Do NOT forget the '?' or '&' in the URL.
    ],

    ...

}
```

## RPC
```
# Basic RPC call.
➜  peth-cli python peth.py  -r eth_blockNumber
0xd80830

# -c to change network.
➜  peth-cli python peth.py  -r eth_blockNumber -c bsc
0xe58858

# RPC call with arguments.
➜  peth-cli python peth.py  -r eth_getBalance 0x0000000000000000000000000000000000000000 latest 
0x2679ce59cfe4a16dd4e

# Raw style.
➜  peth-cli python peth.py  --rpc-call-raw eth_getBlockByNumber '["0x0", false]'                             
{'jsonrpc': '2.0', 'id': 1, 'result': {'difficulty': '0x400000000', 'extraData': '0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa', 'gasLimit': '0x1388', 'gasUsed': '0x0', 'hash': '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'miner': '0x0000000000000000000000000000000000000000', 'mixHash': '0x0000000000000000000000000000000000000000000000000000000000000000', 'nonce': '0x0000000000000042', 'number': '0x0', 'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000', 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'size': '0x21c', 'stateRoot': '0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544', 'timestamp': '0x0', 'totalDifficulty': '0x400000000', 'transactions': [], 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'uncles': []}}
```

## Contract call

Human-readable ABI in peth is like:
- `function name` (`argment type`, [...]) -> (`return value type`, [...])
```
# Call name() of USDT contract.
➜  peth-cli python main.py --to 0xdac17f958d2ee523a2206206994597c13d831ec7 -e "name()->(string)"
Tether USD

# Without return type, we get raw hex data.
➜  peth-cli python main.py --to 0xdac17f958d2ee523a2206206994597c13d831ec7 -e "name()"
0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a5465746865722055534400000000000000000000000000000000000000000000

# When only function name provided, peth will try to auto-extract ABI via the Etherscan API.
➜  peth-cli python main.py --to 0xdac17f958d2ee523a2206206994597c13d831ec7 -e name                                                
Tether USD
➜  peth-cli python main.py --to 0xdac17f958d2ee523a2206206994597c13d831ec7 -e decimals                                            
6

# Call with arguments
➜  peth-cli python main.py --to 0xdac17f958d2ee523a2206206994597c13d831ec7 -e balanceOf 0xdAC17F958D2ee523a2206206994597C13d831ec7
644096679570
```

## console

```
➜  peth-cli python main.py --console
Welcome to the peth shell.   Type help or ? to list commands.
 
peth > ?

Documented commands (type help <topic>):
========================================
balance  bye  contract  erc20  exit  help  nonce  number  quit  storage

peth > number
14158806
peth > balance 0xdAC17F958D2ee523a2206206994597C13D831ec7
1 Wei( 0.0000 Ether)
peth > nonce 0xdAC17F958D2ee523a2206206994597C13D831ec7
1
peth > storage 0xdAC17F958D2ee523a2206206994597C13D831ec7 1
0x000000000000000000000000000000000000000000000000008d7b18430396d4
peth > contract 0xdAC17F958D2ee523a2206206994597C13D831ec7
  SourceCode :   pragma solidity ^0.4.17;
  ABI :  [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string ...
  ContractName :         TetherToken
  CompilerVersion :      v0.4.18+commit.9cf6e910
  OptimizationUsed :     0
  Runs :         0
  ConstructorArguments :         000000000000000000000000000000000000000000000000000000174876e8000000000000000000 ...
  EVMVersion :   Default
  Library :      
  LicenseType :  
  Proxy :        0
  Implementation :       
  SwarmSource :  bzzr://645ee12d73db47fd78ba77fa1f824c3c8f9184061b3b10386beb4dc9236abb28
  === ABI ===
  function name() returns(string ) view
  function deprecate(address _upgradedAddress) returns() nonpayable
  function approve(address _spender,uint256 _value) returns() nonpayable
  function deprecated() returns(bool ) view
  function addBlackList(address _evilUser) returns() nonpayable
  function totalSupply() returns(uint256 ) view
  function transferFrom(address _from,address _to,uint256 _value) returns() nonpayable
  function upgradedAddress() returns(address ) view
  function balances(address ) returns(uint256 ) view
  function decimals() returns(uint256 ) view
  function maximumFee() returns(uint256 ) view
  function _totalSupply() returns(uint256 ) view
  function unpause() returns() nonpayable
  function getBlackListStatus(address _maker) returns(bool ) view
  function allowed(address ,address ) returns(uint256 ) view
  function paused() returns(bool ) view
  function balanceOf(address who) returns(uint256 ) view
  function pause() returns() nonpayable
  function getOwner() returns(address ) view
  function owner() returns(address ) view
  function symbol() returns(string ) view
  function transfer(address _to,uint256 _value) returns() nonpayable
  function setParams(uint256 newBasisPoints,uint256 newMaxFee) returns() nonpayable
  function issue(uint256 amount) returns() nonpayable
  function redeem(uint256 amount) returns() nonpayable
  function allowance(address _owner,address _spender) returns(uint256 remaining) view
  function basisPointsRate() returns(uint256 ) view
  function isBlackListed(address ) returns(bool ) view
  function removeBlackList(address _clearedUser) returns() nonpayable
  function MAX_UINT() returns(uint256 ) view
  function transferOwnership(address newOwner) returns() nonpayable
  function destroyBlackFunds(address _blackListedUser) returns() nonpayable
  constructor (uint256 _initialSupply,string _name,string _symbol,uint256 _decimals) nonpayable
  event Issue(uint256 amount) 
  event Redeem(uint256 amount) 
  event Deprecate(address newAddress) 
  event Params(uint256 feeBasisPoints,uint256 maxFee) 
  event DestroyedBlackFunds(address _blackListedUser,uint256 _balance) 
  event AddedBlackList(address _user) 
  event RemovedBlackList(address _user) 
  event Approval(address owner,address spender,uint256 value) 
  event Transfer(address from,address to,uint256 value) 
  event Pause() 
  event Unpause() 
peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7
totalSupply() -> (uint256) => 39823315849942740
name() -> (string) => Tether USD
symbol() -> (string) => USDT
decimals() -> (uint8) => 6
peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 balanceOf 0xdAC17F958D2ee523a2206206994597C13D831ec7
644096679570
peth > exit
bye!
```