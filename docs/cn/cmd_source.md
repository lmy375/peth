# 源码

## name

打印合约名

```
peth > name 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 WETH9
```

## contract

打印合约信息。如果合约是 Proxy，则自动解析其 Implementation 地址处理。

```
peth > contract 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
  SourceCode :   // Copyright (C) 2015, 2016, 2017 Dapphub
  ABI :  [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string ...
  ContractName :         WETH9
  CompilerVersion :      v0.4.19+commit.c4cbbb05
  OptimizationUsed :     0
  Runs :         200
  ConstructorArguments :         
  EVMVersion :   Default
  Library :      
  LicenseType :  
  Proxy :        0
  Implementation :       
  SwarmSource :  bzzr://deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a
  === VIEWS ===
  0x06fdde03 function name() view returns (string) => Wrapped Ether
  0x18160ddd function totalSupply() view returns (uint256) => 2995376766808380127941716
  0x313ce567 function decimals() view returns (uint8) => 18
  0x95d89b41 function symbol() view returns (string) => WETH
  === OTHERS ===
  fallback()
  0x095ea7b3 function approve(address guy, uint256 wad) returns (bool)
  0x23b872dd function transferFrom(address src, address dst, uint256 wad) returns (bool)
  0x2e1a7d4d function withdraw(uint256 wad)
  0x70a08231 function balanceOf(address) view returns (uint256)
  0xa9059cbb function transfer(address dst, uint256 wad) returns (bool)
  0xd0e30db0 function deposit() payable
  0xdd62ed3e function allowance(address, address) view returns (uint256)
```

## download_json

下载合约对应的 [Standard input json file](https://docs.soliditylang.org/en/v0.8.20/using-the-compiler.html) 文件，该文件可通过 `solc --standard-json` 直接进行编译，得到对应的合约代码。

```
peth > download_json 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
Downloaded as json/api.etherscan.io/WETH9_0.4.19_0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2.json
```

## download_source

下载合约源码。多个合约文件时会自动创建对应的目录结构。

```
peth > download_source 0xe140bB5F424A53e0687bfC10F6845a5672D7e242
Downloaded source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/Spool.sol
Downloaded source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/token/ERC20/IERC20.sol
Downloaded source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/token/ERC20/utils/SafeERC20.sol
Downloaded source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/utils/Address.sol
Downloaded source/api.etherscan.io/0xe140bB5F424A53e0687bfC10F6845a5672D7e242/contracts/external/@openzeppelin/utils/SafeCast.sol
...
```

## diff

对比合约源代码差异。比较合约升级、fork 代码时比较有用。

```
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
```
