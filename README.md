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

# print current block number
peth > number
14158806

# print balance
peth > balance 0xdAC17F958D2ee523a2206206994597C13D831ec7
1 Wei( 0.0000 Ether)

# print nonce
peth > nonce 0xdAC17F958D2ee523a2206206994597C13D831ec7
1

# print specified slot of storage
peth > storage 0xdAC17F958D2ee523a2206206994597C13D831ec7 1
0x000000000000000000000000000000000000000000000000008d7b18430396d4

# print contract information of Etherscan.
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

# print ERC20 information (Call ERC20 view methods)
peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7
totalSupply() -> (uint256) => 39823315849942740
name() -> (string) => Tether USD
symbol() -> (string) => USDT
decimals() -> (uint8) => 6

# Call ERC20 method
peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 balanceOf 0xdAC17F958D2ee523a2206206994597C13D831ec7
644096679570

# Query 4byte database.
peth > 4byte 0x70a08231
passphrase_calculate_transfer(uint64,address)
branch_passphrase_public(uint256,bytes8)
balanceOf(address)

# Extract selector dispatching code and print signatures.
peth > abi4byte 0xdAC17F958D2ee523a2206206994597C13D831ec7
0x6fdde03 name(), message_hour(uint256,int8,uint16,bytes32)
0x753c30c deprecate(address)
0x95ea7b3 approve(address,uint256), sign_szabo_bytecode(bytes16,uint128)
0xe136b19 deprecated()
0xecb93c0 addBlackList(address)
0x18160ddd totalSupply(), voting_var(address,uint256,int128,int128)
0x23b872dd transferFrom(address,address,uint256), gasprice_bit_ether(int128)
0x26976e3f upgradedAddress()
0x27e235e3 balances(address)
0x313ce567 decimals(), available_assert_time(uint16,uint64)
0x35390714 maximumFee()
0x3eaaf86b _totalSupply()
0x3f4ba83a unpause()
0x59bf1abe getBlackListStatus(address)
0x5c658165 allowed(address,address)
0x5c975abb paused()
0x70a08231 balanceOf(address), branch_passphrase_public(uint256,bytes8), passphrase_calculate_transfer(uint64,address)
0x8456cb59 pause()
0x893d20e8 getOwner()
0x8da5cb5b owner(), ideal_warn_timed(uint256,uint128)
0x95d89b41 symbol(), link_classic_internal(uint64,int64)
0xa9059cbb transfer(address,uint256), many_msg_babbage(bytes1), transfer(bytes4[9],bytes5[6],int48[11]), func_2093253501(bytes)
0xc0324c77 setParams(uint256,uint256)
0xcc872b66 issue(uint256)
0xdb006a75 redeem(uint256)
0xdd62ed3e allowance(address,address), remove_good(uint256[],bytes8,bool), _func_5437782296(address,address)
0xdd644f72 basisPointsRate()
0xe47d6060 isBlackListed(address)
0xe4997dc5 removeBlackList(address)
0xe5b5019a MAX_UINT()
0xf2fde38b transferOwnership(address)
0xf3bdc228 destroyBlackFunds(address)

# ERC1967 Proxy
peth > ERC1967 0xC93408bFBEa0Bf3E53bEdBce7D5C1e64db826702
Implementation 0x522808d93ac229cefc17c4be0408520f7e27d26d
Admin 0xedc3be991a29d094ca802b1c92ae6b7f74b53a19
Rollback 0x0000000000000000000000000000000000000000
Beacon 0x0000000000000000000000000000000000000000

# Get code of contract
peth > code 0x4A4651B31d747D1DdbDDADCF1b1E24a5f6dcc7b0
0x608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea2646970667358221220d1429297349653a4918076d650332de1a1068c5f3e07c5c82360c277770b955264736f6c63430007060033

# Print disassembly of contract
peth > disasm 0x4A4651B31d747D1DdbDDADCF1b1E24a5f6dcc7b0
PUSH1 0x80
PUSH1 0x40
MSTORE
PUSH20 0xffffffffffffffffffffffffffffffffffffffff
PUSH1 0x0
SLOAD
AND
PUSH32 0xa619486e00000000000000000000000000000000000000000000000000000000
PUSH1 0x0
CALLDATALOAD
EQ
ISZERO
PUSH1 0x50
JUMPI
....

# Diff contract source.
peth > diff bsc 0x73feaa1eE314F8c655E354234017bE2193C9E24E ftm 0xa71f52aee8311c22b6329EF7715A5B8aBF1c6588
Written to diff/Ownable_ProtonToken_0.16.html
Written to diff/BEP20_ProtofiERC20_0.68.html
Written to diff/CakeToken_ElectronToken_0.62.html
Written to diff/SyrupBar_ElectronToken_0.62.html
Written to diff/MasterChef_ProtofiMasterChef_0.28.html
peth > sh open diff/BEP20_ProtofiERC20_0.68.html
peth > sh open diff/MasterChef_ProtofiMasterChef_0.28.html

# Diff with UniswapV2 factory, pair, router. 
peth > diff uni bsc 0 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0 0
Written to diff/uni_factory/UniswapV2ERC20_PancakeERC20_0.99.html
Written to diff/uni_factory/UniswapV2Pair_PancakePair_0.98.html
Written to diff/uni_factory/UniswapV2Factory_PancakeFactory_0.92.html
Written to diff/uni_pair/UniswapV2ERC20_PancakeERC20_0.99.html
Written to diff/uni_pair/UniswapV2Pair_PancakePair_0.98.html

# Print transcation and receipt.
peth > tx 0xa59c122ee610b8159c669a356cb810d8b6709899ae7f2d906a4e35e2ad4c977d
Transaction:
  blockHash :	 0x9a66081d0dbc10879c27a5a316a0935e52994363f4c20fd557f954cf9c04e93f
  blockNumber :	 15877357
  from :	 0xD0cFE162ef17986ec9Df29C0851F4820a0Bf93C1
  gas :	 58962
  gasPrice :	 5000000000
  hash :	 0xa59c122ee610b8159c669a356cb810d8b6709899ae7f2d906a4e35e2ad4c977d
  input :	 0xa9059cbb000000000000000000000000de21f5bf6d9665934c34491264eefd6b5491c9520000000000000000000000000000000000000000000000000000000b5d43dda8
  nonce :	 14
  to :	 0x40C0Ba4E74D9B95f2647526ee35D6E756FA8BF09
  transactionIndex :	 365
  value :	 0
  type :	 0x0
  v :	 148
  r :	 0xc19e508b9f8f7e0b5e2e7f3213849d0df0d70020f611574f43d375c2988dae12
  s :	 0x1cc66bc14f8cab8322bfaa5fd1ce150a679c2b7d3e15b73c0ba3725a56bee0d7
Receipt:
  blockHash :	 0x9a66081d0dbc10879c27a5a316a0935e52994363f4c20fd557f954cf9c04e93f
  blockNumber :	 15877357
  contractAddress :	 None
  cumulativeGasUsed :	 52296989
  from :	 0xD0cFE162ef17986ec9Df29C0851F4820a0Bf93C1
  gasUsed :	 24308
  logs :	 [AttributeDict({'address': '0x40C0Ba4E74D9B95f2647526ee35D6E756FA8BF09', 'topics': [HexBytes('0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'), HexBytes('0x000000000000000000000000d0cfe162ef17986ec9df29c0851f4820a0bf93c1'), HexBytes('0x000000000000000000000000de21f5bf6d9665934c34491264eefd6b5491c952')], 'data': '0x0000000000000000000000000000000000000000000000000000000b5d43dda8', 'blockNumber': 15877357, 'transactionHash': HexBytes('0xa59c122ee610b8159c669a356cb810d8b6709899ae7f2d906a4e35e2ad4c977d'), 'transactionIndex': 365, 'blockHash': HexBytes('0x9a66081d0dbc10879c27a5a316a0935e52994363f4c20fd557f954cf9c04e93f'), 'logIndex': 1585, 'removed': False})]
  logsBloom :	 0x00000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000100100000000000000000008000000000010000000000000000000000000040000000000000000000000000000000000000001000000000000000010000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000002000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000
  status :	 1
  to :	 0x40C0Ba4E74D9B95f2647526ee35D6E756FA8BF09
  transactionHash :	 0xa59c122ee610b8159c669a356cb810d8b6709899ae7f2d906a4e35e2ad4c977d
  transactionIndex :	 365
  type :	 0x0

# Decode calldata by ABI.
peth > tx_decode 0xa59c122ee610b8159c669a356cb810d8b6709899ae7f2d906a4e35e2ad4c977d
0xD0cFE162ef17986ec9Df29C0851F4820a0Bf93C1 -> 0x40C0Ba4E74D9B95f2647526ee35D6E756FA8BF09
Method:
  0xa9059cbb function transfer(address _receiver, uint256 _amount) returns (bool)
Arguments:
  address _receiver = 0xde21f5bf6d9665934c34491264eefd6b5491c952
  uint256 _amount = 48809369000
peth > tx_decode 0x40C0Ba4E74D9B95f2647526ee35D6E756FA8BF09 0xa9059cbb000000000000000000000000de21f5bf6d9665934c34491264eefd6b5491c9520000000000000000000000000000000000000000000000000000000b5d43dda8
Method:
  0xa9059cbb function transfer(address _receiver, uint256 _amount) returns (bool)
Arguments:
  address _receiver = 0xde21f5bf6d9665934c34491264eefd6b5491c952
  uint256 _amount = 48809369000

# Decode calldata by sig.
peth > tx_decode transfer(address,uint256)->(bool) 0xa9059cbb000000000000000000000000de21f5bf6d9665934c34491264eefd6b5491c9520000000000000000000000000000000000000000000000000000000b5d43dda8
Method:
  0xa9059cbb function transfer(address, uint256) returns (bool)
Arguments:
  address arg1 = 0xde21f5bf6d9665934c34491264eefd6b5491c952
  uint256 arg2 = 48809369000

# Print and decode transactions of specified account.
peth > txs 0x9F403140Bc0574D7d36eA472b82DAa1Bbd4eF327
---- [1] 0xe2c3c86d5f8c14c4a296d6fb3d9e25b84900aa7e0941fd2078b84aa9beb9adc0 14386011 ----
0xc098b2a3aa256d2140208c3de6543aaef5cd3a94 -> 0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 value 219500000000000000
---- [2] 0x40e13c538d9a2cb44573b8580016c2228333a5bee9ac5ded1e7f3d5d2b6b177c 14386127 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 -> 0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f value 100000000000000000
Method:
  0x0f4d14e9 function depositEth(uint256 maxSubmissionCost) payable returns (uint256)
Arguments:
  uint256 maxSubmissionCost = 130102310835
---- [3] 0xfb0cd9b0f81cfee621adea1205eb5c8b4626c1449304bc0142be42c5cb1f9b38 14386138 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 -> 0x99c9fc46f92e8a1c0dec1b1747d010903e884be1 value 100000000000000000
Method:
  0xb1a1a882 function depositETH(uint32 _l2Gas, bytes _data) payable
Arguments:
  uint32 _l2Gas = 1300000
  bytes _data = b''
---- [4] 0x7e4626c81a490a37b64548ad2264af6e2938a66182ab58d46755b2d801fa9436 14386277 ----
0xc098b2a3aa256d2140208c3de6543aaef5cd3a94 -> 0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 value 9999000000000000000
---- [5] 0x620fa3ac2575abef7b4988c0d65820b672cca09ed38ed8caeef0aa7c2535a7fd 14386427 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 -> 0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f value 1500000000000000000
Method:
  0x0f4d14e9 function depositEth(uint256 maxSubmissionCost) payable returns (uint256)
Arguments:
  uint256 maxSubmissionCost = 130102310835
---- [6] 0xcd464b0010144adc20cfbcd70dddf86b8af5154b426662b86f82876d986b2dc4 14386436 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 -> 0x99c9fc46f92e8a1c0dec1b1747d010903e884be1 value 1500000000000000000
Method:
  0xb1a1a882 function depositETH(uint32 _l2Gas, bytes _data) payable
Arguments:
  uint32 _l2Gas = 1300000
  bytes _data = b''
---- [7] 0x0e3c1807419ee4fe5ce94bea9ab3e7bf62b9b7986f22e0789eb9d8dfa94e4360 14388877 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 creates contract 0xc1b15d3b262beec0e3565c11c9e0f6134bdacb36
---- [8] 0x10f2f53b4b705a3a80737736a6135b0a7b643be3032c50b33adaedee4d4bbc18 14388878 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 creates contract 0x2d61dcdd36f10b22176e0433b86f74567d529aaa
---- [9] 0xc033a597ee6bc246a9425608c5c1440a4b4d38cdf6cb3021974134fead219a60 14388880 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 creates contract 0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675
---- [10] 0x69063bd79dd8dac031689848a45905264f360bb25052daf1790a87265b078d23 14388899 ----
0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 creates contract 0x38de71124f7a447a01d67945a51edce9ff491251


# Simple AML command.
peth > aml 0x9F403140Bc0574D7d36eA472b82DAa1Bbd4eF327
Start 0x9F403140Bc0574D7d36eA472b82DAa1Bbd4eF327
[1] 0xc098b2a3aa256d2140208c3de6543aaef5cd3a94 sends 0x9f403140bc0574d7d36ea472b82daa1bbd4ef327 0.21950 ETH
[2] 0x366064cc2baa69ff0bb0dd7dd07cb266e5105759 sends 0xc098b2a3aa256d2140208c3de6543aaef5cd3a94 0.09924 ETH
[3] 0xfa453aec042a837e4aebbadab9d4e25b15fad69d sends 0x366064cc2baa69ff0bb0dd7dd07cb266e5105759 0.10000 ETH
[4] 0x0c7719f1d7ed41271cbba92ec153afa6610228f8 sends 0xfa453aec042a837e4aebbadab9d4e25b15fad69d 9.99389 ETH
[5] 0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98 sends 0x0c7719f1d7ed41271cbba92ec153afa6610228f8 9.99400 ETH
[6] 0x32be343b94f860124dc4fee278fdcbd38c102d88 sends 0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98 4.99000 ETH
[7] 0x543807d0af2c58b49d7f25659d0472d4d8b8e8da sends 0x32be343b94f860124dc4fee278fdcbd38c102d88 105.98950 ETH
[8] 0xaf880fc7567d5595cacce15c3fc14c8742c26c9e sends 0x543807d0af2c58b49d7f25659d0472d4d8b8e8da 1.00000 ETH
[9] GENESIS sends 0xaf880fc7567d5595cacce15c3fc14c8742c26c9e 133.70000 ETH
End

peth > aml 0x629e7Da20197a5429d30da36E77d06CdF796b71A
Start 0x629e7Da20197a5429d30da36E77d06CdF796b71A
[1] 0xD6187b4a0f51355A36764558D39b2C21aC12393D calls contract TornadoProxy(0x722122dF12D4e14e13Ac3b6895a86e84145b6967) in 0xb3283c7c82faa1b6b0d3b8104e87a5239f909ea6d8eeb4026a6d5b671a672f66
End

# Happy end.
peth > exit
bye!
```

All commands in the console can be executed via `--cmd`. 
```
➜  peth-cli git:(master) ✗ python main.py --cmd number
14210380
➜  peth-cli git:(master) ✗ python main.py --cmd balance 0xdAC17F958D2ee523a2206206994597C13D831ec7
1 Wei( 0.0000 Ether)
```