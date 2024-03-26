# Source

## name

Print the contract name.

```
peth > name 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 WETH9
```

## contract

Print contract information. If the contract is a Proxy, the implementation source will be used.

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

Download the [Standard input json file](https://docs.soliditylang.org/en/v0.8.20/using-the-compiler.html) corresponding to the contract address, this file can be directly compiled through `solc --standard-json` to get the corresponding contract bytecode.

```
peth > download_json 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
Downloaded as json/api.etherscan.io/WETH9_0.4.19_0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2.json
```

## download_source

Download contract source code. When there are multiple contract files, the corresponding directory structure will be automatically created.

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

Compare contract source code differences. It is useful for comparing contract upgrades and forked projects.

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
