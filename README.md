# Peth

A python Ethereum utilities command-line tool.

`Peth`, pronounced like `Peace`, wishes to become the *Swiss Army Knife* guarding the Ethereum space.

`Peth` 发音与和平（`Peace`）相近，是一款以太坊命令行工具。愿景是成为以太坊世界的瑞士军刀。

# Install 安装

## From pip 

1. Install with pip. 通过 pip 安装。
```
$ python -m venv test
$ source test/bin/activate

$ pip install peth
# or
$ pip install git+https://github.com/lmy375/peth
```

2. Run peth。运行 peth。
```
$ peth -h
```

## From source

1. Clone the repo. 克隆本仓库。

```
git clone https://github.com/lmy375/peth
```
2. (Optional) Edit `config.json` with new EVM network RPC endpoints and your Etherscan API keys. （可选的）编辑根目录下的 `config.json` 文件，添加自定义的 RPC 地址。添加 API Key 可以提高执行速度（否则限频时会自动等待）。

```json
{
    "chains": {
        "eth": [
            // RPC endpoint URL.
            "https://rpc.ankr.com/eth",  

            // Etherscan-style API URL.
            // Get better experience if you have an API key.
            // https://api.etherscan.io/api?apikey=<Your API Key>&
            // Do NOT forget the '?' or '&' in the URL.
            "https://api.etherscan.io/api?",
            
            // Etherscan address page URL.
            "https://etherscan.io/address/"
        ],

      ...
    }
}
```

3. Run `python -m peth`. 在目录下执行 `python -m peth`。

```sh
$ python -m peth
Welcome to the peth shell. Type `help` to list commands.

peth > help

Documented commands (type help <topic>):
========================================
abi4byte          config           erc20         ipython  proxy      signer
abi_encode        contract         estimate_gas  log      proxy_all  storage
aes               debank           eth_call      loop     py         timelock
aml               debug            eth_call_raw  name     quit       timestamp
balance           decompile        exit          nonce    rpc_call   tx
bye               deth             factory       number   run        tx_raw
calldata_decode   diff             gnosis        open     send_tx    tx_replay
chain             diffasm          graph         oracle   sender     txs
code              disasm           help          owner    sh         url
codesize          download_json    idm           pair     sha3       verify
common_addresses  download_source  int           price    sig        view

peth >
```

# Usage 使用说明 

## SDK 

```
In [1]: from peth.core.peth import Peth

In [2]: p = Peth.get_or_create('eth')

In [3]: p.rpc_call('eth_blockNumber')
Out[3]: '0xf66715'

In [4]: p.rpc_call('eth_getBalance', ['0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 'latest'])
Out[4]: '0x84c3181015c16f220'

In [5]: p.call_contract('0xdAC17F958D2ee523a2206206994597C13D831ec7', 'balanceOf(address)->(uint256)', ['0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'])
Out[5]: 72201976
```

## Command-line options 命令行参数 

```sh
# Basic RPC call.
# 执行基本的 RPC call
# 参考 https://eth.wiki/json-rpc/API
$ peth -r eth_blockNumber
0xe0aabb

# -c to change network.
# 使用 -c 指定使用的区块链网络。支持的网络见 config.json
$ peth  -r eth_blockNumber -c bsc
0x10c158f

# RPC call with arguments.
# 带参数的 RPC 调用
$ peth  -r eth_getBalance 0x0000000000000000000000000000000000000000 latest
0x268fd6968816d5aaeb0

# Raw style.
# 直接指定参数 JSON 字符串
$ peth  --rpc-call-raw eth_getBlockByNumber '["0x0", false]'
{'jsonrpc': '2.0', 'id': 0, 'result': {'difficulty': '0x400000000', 'extraData': '0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa', 'gasLimit': '0x1388', 'gasUsed': '0x0', 'hash': '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'miner': '0x0000000000000000000000000000000000000000', 'mixHash': '0x0000000000000000000000000000000000000000000000000000000000000000', 'nonce': '0x0000000000000042', 'number': '0x0', 'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000', 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'size': '0x21c', 'stateRoot': '0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544', 'timestamp': '0x0', 'totalDifficulty': '0x400000000', 'transactions': [], 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'uncles': []}}

# Call name() of USDT contract.
# 调用 USDT 合约的 name 方法
$ peth --to 0xdac17f958d2ee523a2206206994597c13d831ec7 -e "name()->(string)"
Tether USD

# Run peth command.
# 执行 peth 内置命令。
$ peth --cmd number
14723791
```

## Peth console 控制台

The recommanded way to use `peth` is the interactive console mode.

相比上面的单条命令行方式，更推荐的使用方式是使用交互式的 peth console。

```sh
$ peth
Welcome to the peth shell. Type `help` to list commands.

peth >
```

### Config 配置类命令

```sh
# Change network to BSC.
# 切换网络。
peth > chain bsc
Current:
Chain: eth
RPC: https://rpc.ankr.com/eth
API: https://api.etherscan.io/api?
Address: https://etherscan.io/address/
Changed:
Chain: bsc
RPC: https://rpc.ankr.com/bsc
API: https://api.bscscan.com/api?
Address: https://bscscan.com/address/

# Change sender in eth_call
# 切换合约调用时的使用的 msg.sender
peth > sender 0xdac17f958d2ee523a2206206994597c13d831ec7
Old: 0x0000000000000000000000000000000000000000
New: 0xdac17f958d2ee523a2206206994597c13d831ec7

# Exit console.
# 退出。
peth > exit
```

### Utilities 工具类命令

```sh
# Execute shell commands.
# 执行原生 bash 命令。
peth > sh ls
README.md		__pycache__		config.json		core			eth			main.py			output			requirements.txt	tests			util
peth > ! ls
README.md		__pycache__		config.json		core			eth			main.py			output			requirements.txt	tests			util

# Evaluate python expressions.
# 解析 python 表达式（常用于当计算器）
peth > py int(1e18)*100
100000000000000000000
peth > ? int(1e18)*100
100000000000000000000

# Open URL or file.
# 打开链接或者文件。
peth > open https://www.google.com/
peth > open README.md	

# List some contract address
# 打印出一些常见地址
peth > common_addresses
Name                                     Chain      Address
PancakeMasterChef                        bsc        0x73feaa1eE314F8c655E354234017bE2193C9E24E
PancakePair                              bsc        0x0eD7e52944161450477ee417DE9Cd3a859b14fD0

# Calculate SHA3 hash.
# 计算 SHA3 哈希
peth > sha3 balanceOf()
722713f7196651d0fe4592d1dc3ef527a8f2d47259e18fa8ec48288f351a83eb

# Query the selector in https://www.4byte.directory/
# 根据 selector 反查函数签名
peth > 4byte 722713f7
balanceOf()

peth > 4byte transferFrom(address,address,uint256)
0x030e30df super_transferFrom(address,address,uint256)
0x09d6796f our_transferFrom(address,address,uint256)
0x23b872dd transferFrom(address,address,uint256)
0x3642e004 lexDAOtransferFrom(address,address,uint256)
0x3c1008bb internal_transferFrom(address,address,uint256)
0x5ec7b353 safetransferFrom(address,address,uint256)
0xcb712535 _transferFrom(address,address,uint256)
0xd05391d2 admin_transferFrom(address,address,uint256)
8 item(s) found in 4byte.json.
Full match: 0x23b872dd transferFrom(address,address,uint256)

# ABI encode.
peth > abi_encode test(uint256,string,address,string) 0x1000 "AAAA" 0x418e63cab75812661b055e111336dfc32951135d "BBBB"
0xeb7f0ebe00000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000418e63cab75812661b055e111336dfc32951135d00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000004414141410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044242424200000000000000000000000000000000000000000000000000000000

# ABI decode. 
# With known selector.
peth > abi_decode 0xa9059cbb000000000000000000000000418e63cab75812661b055e111336dfc32951135d000000000000000000000000000000000000000000000000000000000c28cb00
1 selectors found.
Method:
  0xa9059cbb function transfer(address, uint256)
Arguments:
  address arg1 = ReversibleDemo(0x418e63cab75812661b055e111336dfc32951135d)
  uint256 arg2 = 204000000

# With unknown selector.
peth > abi_decode 0xeb7f0ebe00000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000418e63cab75812661b055e111336dfc32951135d00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000004414141410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044242424200000000000000000000000000000000000000000000000000000000
No selector found for 0xeb7f0ebe.
Guessing types ...
[0]   uint256   4096(0x1000)
[1]   string   AAAA
[2]   address   0x418e63cab75812661b055e111336dfc32951135d
[3]   string   BBBB

# Print number.
# 打印 int 数（方便 Token 余额转换）
peth > int 100000000000000000000
Value: 100000000000000000000
Value/1e18: 100.0
Value/1e6: 100000000000000.0

# Convert UNIX timestamp to local datetime, or convert seconds to hours / days.
# 时间戳转化（时长大于10年，则认为是时间段，而不是时间戳）
peth > timestamp 1651845252
2022-05-06 21:54:12
peth > timestamp 3600
3600 secs
= 1.0 hours
= 0.0 days
```

### ETH basic 以太坊基础命令

```sh
# print current block number
# 打印当前区块数
peth > number
17569820

# print balance
# 打印地址当前余额
peth > balance 0xdAC17F958D2ee523a2206206994597C13D831ec7
1 Wei( 0.0000 Ether)

# print nonce
# 打印地址 nonce
peth > nonce 0xdAC17F958D2ee523a2206206994597C13D831ec7
1

# print specified slot of storage
# 获取合约地址中 storage 指定 slot 的值
peth > storage 0xdAC17F958D2ee523a2206206994597C13D831ec7 1
0x000000000000000000000000000000000000000000000000008d7b18430396d4

# Get code of contract
# 打印合约字节码
peth > code 0xdAC17F958D2ee523a2206206994597C13D831ec7
0x606060405260043610610196576000357c01000 ...

# Get size of contract
# 打印合约字节码长度（可用于判断账户是否是合约）
peth > codesize 0xdAC17F958D2ee523a2206206994597C13D831ec7
Size 11075
peth > codesize 0x0000000000000000000000000000000000000000
Size 0

# Call contract view function. 
# 调用合约的 view 函数。
peth > eth_call 0xdac17f958d2ee523a2206206994597c13d831ec7 name()->(string)
Tether USD

# If full ABI is not provided, peth fetch the ABI from Etherscan.
# 也可以只提供函数名，peth 会自动通过 Etherscan 获取 ABI 信息。
peth > eth_call 0xdac17f958d2ee523a2206206994597c13d831ec7 name
Tether USD
```

### Contract 合约特殊命令

```sh
# Get property value of the contract.
# 获取合约某个属性值（调用无参 View 方法，可指定类型）
peth > view 0xdac17f958d2ee523a2206206994597c13d831ec7 name
0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a5465746865722055534400000000000000000000000000000000000000000000
peth > view 0xdac17f958d2ee523a2206206994597c13d831ec7 name string
Tether USD

# Print ERC20 information
# 打印 ERC20 信息
peth > erc20 0xdac17f958d2ee523a2206206994597c13d831ec7
totalSupply()->(uint256) => 39815550064061448
name()->(string) => Tether USD
symbol()->(string) => USDT
decimals()->(uint8) => 6

# Print proxy information
# 打印代理信息
peth > proxy 0xdD4051c3571C143b989C3227E8eB50983974835C
0xdD4051c3571C143b989C3227E8eB50983974835C is an ERC-1967 Proxy
Implementation: 0xeabe9aa60e7da3a962b39942fb3c3568b7c57c1d Controller
Admin: 0x0e1dde6cd48758482528b718ef8d27a7e69eae62 ProxyAdmin
Beacon: 0x0000000000000000000000000000000000000000 EOA

# Print owner information of Ownable contract.
# 打印合约的 owner 信息
peth > owner 0x0e1dDE6CD48758482528B718EF8d27a7E69EAE62
Owner: 0xf8e5227add01b2b8f36981a2566c160e5e4136e4
EOA

# Print Gnosis information.
# 打印 Gnosis 多签信息
peth > gnosis 0xF6Bc2E3b1F939C435D9769D078a6e5048AaBD463
Version: 1.3.0
Policy: 5/8
Owners:
  0x01bb2320faea7f514b790a04812461112687bb19 EOA
  0x4cc02225a3d7636af61d3903b2cba838a6f54ac2 EOA
  0x587b28fad1132fd3ac50cb38342e2c6ca7dc670a EOA
  0xcc16c45be95773e9da59d42a575b169b23d4f58d EOA
  0xa286844303f5207658bc2a6ef582099295501f5e EOA
  0x6cee7a18072c5d26e99d186ead6feb9f17d5ac9e EOA
  0x64dcf80aa31f40d094cfb2d578019bcb2eccf58b EOA
  0x46ff1b2b030201f572e22fc18c26974ec8fe8819 EOA
Impl: 0xd9db270c1b5e3bd161e8c8503c55ceabee709552

# Print timelock information
# 打印时间锁合约信息
peth > timelock 0x574703381d4cb4eeb474e43eee97e3d9986e48a7
Min Delay: 0s = 0.00h
Max Delay: 2592000s = 720.00h
Current Delay: 0s = 0.00h
Admin: 0xa42f6fb68607048dde54fcd53d2195cc8ca5f486 GnosisSafe 3/5

# Print Uniswap pair information.
# 打印 Uniswap 类型交易对信息
peth > pair 0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852
TokenPair: 0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852
WETH 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 18
USDT 0xdac17f958d2ee523a2206206994597c13d831ec7 6
Reseves: 24821.6555 WETH, 66468321.6535 USDT
Price:
1 WETH = 2677.8360 USDT
1 USDT = 0.0004 WETH

# Print ChainLink Oracle information.
# 打印 ChainLink 预言机信息
peth > oracle 0xdeb288f737066589598e9214e782fa5a8ed689e8
Aggregator: 0x81076d6ff2620ea9dd7ba9c1015f0d09a3a732e6
Description: BTC / ETH
Owner: 0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca
Decimals: 18
Latest Answer: 13297486710000000000 (13.30)
Max Answer: 10000000000000000000000 (10000.00)
Min Answer: 100000000000000000 (0.10)
16 Transmitters:
  0x57cd4848b12469618b689163f507817940acca02
  0xcc29be4ca92d4ecc43c8451fba94c200b83991f6
  0x64c735d72eab90c04da523b6b9895773acb60f5d
  0xa938d77590af1d98bab7dc4a0bde594fc3f9c403
  0x2a4a7afa40a9d03b425752fb4cfd5f0ff5b3964c
  0x9cfab1513ffa293e7023159b3c7a4c984b6a3480
  0xf42336e35d5c1d1d0db3140e174bcfc3945f6822
  0xf16e77a989529aa4c58318acee8a1548df3fccc1
  0x8b1d49a93a84b5da0917a1ed42d8a3e191c28524
  0x7bfb89db2d7217c57c3ad3d4b55826efd17dc2e9
  0xbbf078a8849d74623e36e6dbbdc8e0a35e657c26
  0x43793ee58e0a3d920e3e4a115a9fa07dc4b09715
  0x0312ea121df0a323ff535b753172736cc9d53d13
  0xc4b732fd121f2f3783a9ac2a6c62fd535fd13fda
  0x5a6fcc02d8c50ea58a22115a7c4608b723030016
  0xe3e0596ac55ae6044b757bab27426f7dc9e018d4
```


### Transaction 交易类命令

```sh
# Print decoded transaction information with txid.
# 打印解码后的合约调用信息。
peth > tx 0x1f26956899a5d6754b1b765794bf8b5daef994357a817209a6d84498da026922
From: 0x17F96db7cf1D3964F3Cd32E98AFE9Eb43A15fe24
To: 0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852
Method: function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes data) returns ()
Arguments:
     amount0Out : 21829054100743363759
     amount1Out : 0
     to : 0x0302c1e37200005183c900a30000aa005eaf710c
     data : 11b815efb8f581194ae79006d24e0d814b7697f6c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000010b1f962fa00000000000000000000000000000000000000000000000000630d453738095301
ERC20 Transfers:
  WETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) to->0x0302c1E37200005183c900A30000Aa005eaF710C 21829054100743363759
  USDT(0xdAC17F958D2ee523a2206206994597C13D831ec7) 0x11b815efB8f581194ae79006d24E0d814B7697F6->to 71705387770
  WETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) 0x0302c1E37200005183c900A30000Aa005eaF710C->0x11b815efB8f581194ae79006d24E0d814B7697F6 21801173487118685020
  WETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) 0x0302c1E37200005183c900A30000Aa005eaF710C->0x0000E0Ca771e21bD00057F54A68C30D400000000 27880613624678739

# Print decoded transaction information with address and calldata.
# 也可以直接指定合约地址及数据（解析多签或者时间锁交易时常用）
peth > tx 0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852 0x022c0d9f0000000000000000000000000000000000000000000000012ef0610ca1979caf00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000302c1e37200005183c900a30000aa005eaf710c0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000006911b815efb8f581194ae79006d24e0d814b7697f6c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000010b1f962fa00000000000000000000000000000000000000000000000000630d4537380953010000000000000000000000000000000000000000000000
Method: function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes data) returns ()
Arguments:
     amount0Out : 21829054100743363759
     amount1Out : 0
     to : 0x0302c1e37200005183c900a30000aa005eaf710c
     data : 11b815efb8f581194ae79006d24e0d814b7697f6c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000010b1f962fa00000000000000000000000000000000000000000000000000630d453738095301
    
# Print transaction history of address.
# 打印某个地址多条的交易信息
peth > txs 0xf8E5227aDD01b2b8f36981a2566c160E5E4136e4
---- [1] 0x83ad34dde3cf458b904110747b0390d3cbd34cfe7038d1b996b2be7219ac9f06 14484519 ----
0x2ed297968850f81144adca7aed34fac375643e46 -> 0xf8e5227add01b2b8f36981a2566c160e5e4136e4 value 5044300830232571940
---- [2] 0xbe906287eaacbcbc25a9ab9528faf4fdd23fa8ffb512836bab18720b46a50716 14484670 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract SpoolOwner(0x4f03f70a99e5c3b49d733ddd7458f80fa9b5a5b5)
---- [3] 0x022716d5bc20790246d2e08e7f24dd0c42a5840231f537a58fb658cb5c0c8531 14486465 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract AaveStrategy(0x854db91e371e42818936e646361452c3060ec9dd)
---- [4] 0x129459268bf44c2837fa04af38c386c0266fc1c3b03b4fb0ac56ddb49f2f4941 14486467 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract AaveStrategy(0x21d24ad1a66bd35447365d5adaa3530ae3695781)
---- [5] 0x44314234de5e43de33a52710c1a6e97ad2a87075ea7f79f1612ac481ba3cbbf0 14486468 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract AaveStrategy(0x6f4dad966d7ea29f1e2f106da547c66f4df0e8e5)
---- [6] 0xc7a825f8d24365def18a3c7c4395a29adc4cc81c7d8a81e90d595d60aa8a5487 14486469 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract Curve3poolStrategy(0x55fc10a40f0056c28b953b5da3dc53679e70bf70)
---- [7] 0xae00264f3a2533b4189451b4996b6a24b2f702916a340cdf540fb1db77b57018 14486470 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract Curve3poolStrategy(0xa249f52f8ea0048c9d6e55eb0a8de06b67affe67)
---- [8] 0x7d5a44387d06c1b15472c86615f47bf0d7988fcb65cda017d789370fd9594288 14486472 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract Curve3poolStrategy(0x9ab6f67285151563f7675cf365e42841c243455e)
---- [9] 0xd0658a9e55f90f634a904e14da37dfda8e9218d6c73cd9ebf5a7a9fb74b2af44 14486475 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract HarvestStrategy(0xa97a5fea16c9881254be77e4f3adf8e23c3f5bd4)
---- [10] 0x38031a9798683c78136dc23e38cc51dde4001482d0f12701ee84fc32398fb8c7 14486476 ----
0xf8e5227add01b2b8f36981a2566c160e5e4136e4 creates contract HarvestStrategy(0xb84cd9b5548ee1538ca50b947fa99adf5fd85e78)
```
### Bytecode 字节码类工具

```sh
# Print assembly code of address.
# 打印反汇编后的合约字节码
peth > disasm 0xdD4051c3571C143b989C3227E8eB50983974835C
PUSH1 0x80
PUSH1 0x40
MSTORE
PUSH1 0x4
CALLDATASIZE
LT
PUSH2 0x5e
JUMPI
PUSH1 0x0
CALLDATALOAD
PUSH1 0xe0
...

# Extract selector dispatching code and print signatures.
# 获取合约可能的 selector （根据 PUSH4 指令提取，会有误报），分析闭源合约常用。
peth > abi4byte 0xdAC17F958D2ee523a2206206994597C13D831ec7
0x06fdde03 name()            	 0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a5465746865722055534400000000000000000000000000000000000000000000
0x0753c30c deprecate(address)
0x095ea7b3 approve(address,uint256)
0x0ecb93c0 addBlackList(address)
0x18160ddd totalSupply()            	 0x000000000000000000000000000000000000000000000000009c5715d89b008f
0x23b872dd transferFrom(address,address,uint256)
0x26976e3f upgradedAddress()            	 0x0000000000000000000000000000000000000000000000000000000000000000
0x27e235e3 balances(address)
0x313ce567 decimals()            	 0x0000000000000000000000000000000000000000000000000000000000000006
0x3eaaf86b _totalSupply()            	 0x000000000000000000000000000000000000000000000000009c5715d89b008f
0x3f4ba83a unpause()
0x59bf1abe getBlackListStatus(address)
0x5c658165 allowed(address,address)
0x5c975abb paused()            	 0x0000000000000000000000000000000000000000000000000000000000000000
0x70a08231 balanceOf(address)
0x8456cb59 pause()
0x893d20e8 getOwner()            	 0x000000000000000000000000c6cde7c39eb2f0f0095f41570af89efc2c1ea828
0x8da5cb5b owner()            	 0x000000000000000000000000c6cde7c39eb2f0f0095f41570af89efc2c1ea828
0x95d89b41 symbol()            	 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000045553445400000000000000000000000000000000000000000000000000000000
0xa9059cbb transfer(address,uint256)
0xc0324c77 setParams(uint256,uint256)
0xcc872b66 issue(uint256)
0xdb006a75 redeem(uint256)
0xdd62ed3e allowance(address,address)
0xdd644f72 basisPointsRate()            	 0x0000000000000000000000000000000000000000000000000000000000000000
0xe47d6060 isBlackListed(address)
0xe4997dc5 removeBlackList(address)
0xe5b5019a MAX_UINT()            	 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
0xf2fde38b transferOwnership(address)
0xf3bdc228 destroyBlackFunds(address)
0xaee92d33 approveByLegacy(address,address,uint256)
0x8b477adb transferFromByLegacy(address,address,address,uint256)
0x6e18980a transferByLegacy(address,address,uint256)
```

### Source 源码类工具

```sh
# Print contract information of Etherscan.
# 打印合约信息（会自动调用所有无参 View 方法）
peth > contract 0xdAC17F958D2ee523a2206206994597C13D831ec7
  SourceCode :	 pragma solidity ^0.4.17;
  ABI :	  ...
  ContractName :	 TetherToken
  CompilerVersion :	 v0.4.18+commit.9cf6e910
  OptimizationUsed :	 0
  Runs :	 0
  ConstructorArguments :	 000000000000000000000000000000000000000000000000000000174876e8000000000000000000 ...
  EVMVersion :	 Default
  Library :
  LicenseType :
  Proxy :	 0
  Implementation :
  SwarmSource :	 bzzr://645ee12d73db47fd78ba77fa1f824c3c8f9184061b3b10386beb4dc9236abb28
  === VIEWS ===
  0x06fdde03 function name() view returns (string) => Tether USD
  0x0e136b19 function deprecated() view returns (bool) => False
  0x18160ddd function totalSupply() view returns (uint256) => 39815550064061448
  0x26976e3f function upgradedAddress() view returns (address) => 0x0000000000000000000000000000000000000000
  0x313ce567 function decimals() view returns (uint256) => 6
  0x35390714 function maximumFee() view returns (uint256) => 0
  0x3eaaf86b function _totalSupply() view returns (uint256) => 39815550064061448
  0x5c975abb function paused() view returns (bool) => False
  0x893d20e8 function getOwner() view returns (address) => 0xC6CDE7C39eB2f0F0095F41570af89eFC2C1Ea828
  0x8da5cb5b function owner() view returns (address) => 0xC6CDE7C39eB2f0F0095F41570af89eFC2C1Ea828
  0x95d89b41 function symbol() view returns (string) => USDT
  0xdd644f72 function basisPointsRate() view returns (uint256) => 0
  0xe5b5019a function MAX_UINT() view returns (uint256) => 115792089237316195423570985008687907853269984665640564039457584007913129639935
  === OTHERS ===
  0x0753c30c function deprecate(address _upgradedAddress)
  0x095ea7b3 function approve(address _spender, uint256 _value)
  0x0ecb93c0 function addBlackList(address _evilUser)
  0x23b872dd function transferFrom(address _from, address _to, uint256 _value)
  0x27e235e3 function balances(address) view returns (uint256)
  0x3f4ba83a function unpause()
  0x59bf1abe function getBlackListStatus(address _maker) view returns (bool)
  0x5c658165 function allowed(address, address) view returns (uint256)
  0x70a08231 function balanceOf(address who) view returns (uint256)
  0x8456cb59 function pause()
  0xa9059cbb function transfer(address _to, uint256 _value)
  0xc0324c77 function setParams(uint256 newBasisPoints, uint256 newMaxFee)
  0xcc872b66 function issue(uint256 amount)
  0xdb006a75 function redeem(uint256 amount)
  0xdd62ed3e function allowance(address _owner, address _spender) view returns (uint256)
  0xe47d6060 function isBlackListed(address) view returns (bool)
  0xe4997dc5 function removeBlackList(address _clearedUser)
  0xf2fde38b function transferOwnership(address newOwner)
  0xf3bdc228 function destroyBlackFunds(address _blackListedUser)

# Print contract name.
# 打印合约名（或 EOA)
peth > name 0xdAC17F958D2ee523a2206206994597C13D831ec7
0xdAC17F958D2ee523a2206206994597C13D831ec7 TetherToken
peth > name 0x0000000000000000000000000000000000000000
0x0000000000000000000000000000000000000000 EOA

# Diff contract source code.
# 对比合约源码差异。
peth > diff bsc 0x73feaa1eE314F8c655E354234017bE2193C9E24E ftm 0xa71f52aee8311c22b6329EF7715A5B8aBF1c6588
[*] Diff bsc-0x73feaa1eE314F8c655E354234017bE2193C9E24E  ftm-0xa71f52aee8311c22b6329EF7715A5B8aBF1c6588
Written to output/diff/SAMENAME_SafeMath_0.85.html
Written to output/diff/SAMENAME_Address_0.72.html
Written to output/diff/SafeBEP20_SafeERC20_0.62.html
Written to output/diff/BEP20_ProtofiERC20_0.85.html
Written to output/diff/CakeToken_ElectronToken_0.59.html
Written to output/diff/SyrupBar_ElectronToken_0.57.html
Non-matched contracts:
Context,Ownable,MasterChef
----------
ProtofiMasterChef,ProtonToken
peth > open output/diff/SAMENAME_SafeMath_0.85.html


# Open blockchain explorer of the address.
# 打开区块链浏览器对应地址（会自动唤起浏览器）
peth > url 0xdAC17F958D2ee523a2206206994597C13D831ec7
https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7

# Download solc standard input json, which can be compile with `solc --standard-json`
# 下载 solidity 的标准 JSON 格式源码，可以直接使用 solc --standard-json 进行编译。
peth > download_json 0xdAC17F958D2ee523a2206206994597C13D831ec7
Downloaded as output/json/api.etherscan.io/TetherToken_0.4.18_0xdAC17F958D2ee523a2206206994597C13D831ec7.json

# Download source.
# 下载源码（多文件时会创建对应的文件目录结构）
peth > download_source 0xe140bB5F424A53e0687bfC10F6845a5672D7e242
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/Spool.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/token/ERC20/IERC20.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/token/ERC20/utils/SafeERC20.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/utils/Address.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/utils/SafeCast.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/interfaces/IBaseStrategy.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/interfaces/IController.sol
Downloaded output/source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/interfaces/ISpoolOwner.sol
...


# Run solidity file through eth_call.
# 利用 eth_call 执行 solidity 代码。
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
972099416751514
```

###  Others 其他

Read the code.

参考源码。