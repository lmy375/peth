# DApp

## view

View the variable value of a contract. 

The value type can be specified.

```
peth > view 0xdAC17F958D2ee523a2206206994597C13D831ec7 symbol
0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000045553445400000000000000000000000000000000000000000000000000000000

peth > view 0xdAC17F958D2ee523a2206206994597C13D831ec7 symbol string
USDT
```

## erc20

Print information of an ERC20 Token.
```
peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 
Name: Tether USD
Symbol: USDT
decimals: 6
totalSupply: 48999156520373530
```

Can also be used to call ERC20 contract methods.

```
peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 symbol
USDT

peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 s
USDT

peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 balanceOf 0xdAC17F958D2ee523a2206206994597C13D831ec7
229943573161

peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7 b 0xdAC17F958D2ee523a2206206994597C13D831ec7
229943573161
```

## proxy

Print ERC-1967 proxy information.

```
peth > proxy 0x858646372CC42E1A627fcE94aa7A7033e7CF075A
0x858646372CC42E1A627fcE94aa7A7033e7CF075A is an ERC-1967 Proxy
Implementation: 0x5d25eef8cfedaa47d31fe2346726de1c21e342fb StrategyManager
Admin: 0x8b9566ada63b64d1e1dcf1418b43fd1433b72444 ProxyAdmin
Beacon: 0x0000000000000000000000000000000000000000 EOA
ProxyAdmin owner:
Owner: 0x369e6f597e22eab55ffb173c6d9cd234bd699111 GnosisSafe 1/2
```

## owner

Call the contract's `owner()` method and print result.

```
peth > owner 0x8b9566ada63b64d1e1dcf1418b43fd1433b72444
Owner: 0x369e6f597e22eab55ffb173c6d9cd234bd699111 GnosisSafe 1/2
```

## safe

Print `Safe{Wallet}` (formerly `Gnosis Safe`) information.

```
peth > safe 0x369e6f597e22eab55ffb173c6d9cd234bd699111
Version: 1.3.0
Policy: 1/2
Owners:
  0xa6db1a8c5a981d1536266d2a393c5f8ddb210eaf Timelock
  0xfea47018d632a77ba579846c840d5706705dc598 GnosisSafe 9/13
Impl: 0xd9db270c1b5e3bd161e8c8503c55ceabee709552
```

## timelock

Print timelock information.

```
peth > timelock 0xa6db1a8c5a981d1536266d2a393c5f8ddb210eaf
Min Delay: 172800s = 48.00h
Max Delay: 2592000s = 720.00h
Current Delay: 864000s = 240.00h
Admin: 0xbe1685c81aa44ff9fb319dd389addd9374383e90 GnosisSafe 3/6
```

## pair

Print UniswapV2-fork DEX pair information.
```
peth > pair 0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852
TokenPair: 0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852
WETH 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 18
USDT 0xdac17f958d2ee523a2206206994597c13d831ec7 6
Reseves: 18603.8263 WETH, 67971743.3326 USDT
V2 Price:
1 WETH = 3653.6432 USDT
1 USDT = 0.0003 WETH
```

## factory

Print all pair information in Uniswap V2 Factory.

```
peth > factory 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f
313954 pairs found.
[0] 0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc
TokenPair: 0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc
USDC 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 6
WETH 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 18
Reseves: 47013378.5775 USDC, 12860.4069 WETH
V2 Price:
1 USDC = 0.0003 WETH
1 WETH = 3655.6681 USDC
[1] 0x3139ffc91b99aa94da8a2dc13f1fc36f9bdc98ee
TokenPair: 0x3139ffc91b99aa94da8a2dc13f1fc36f9bdc98ee
USDP 0x8e870d67f660d95d5be530380d0ec0bd388289e1 18
USDC 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 6
Reseves: 6.7295 USDP, 6.7772 USDC
V2 Price:
1 USDP = 1.0071 USDC
1 USDC = 0.9930 USDP
...
```

## oracle

Print the ChainLink oracle information.

```
peth > oracle 0xdeb288f737066589598e9214e782fa5a8ed689e8
Aggregator: 0x81076d6ff2620ea9dd7ba9c1015f0d09a3a732e6
Proxy Owner: 0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca
Aggregator Owner: 0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca
Version: 4
Description: BTC / ETH
Decimals: 18
Latest Answer: 19452809156463572000 (19.45)
Max Answer: 10000000000000000000000 (10000.00)
Min Answer: 100000000000000000 (0.10)
16 Transmitters:
  0x57cd4848b12469618b689163f507817940acca02
  0xcc29be4ca92d4ecc43c8451fba94c200b83991f6
  0x64c735d72eab90c04da523b6b9895773acb60f5d
  0xa938d77590af1d98bab7dc4a0bde594fc3f9c403
  0x2a4a7afa40a9d03b425752fb4cfd5f0ff5b3964c
  0x9cfab1513ffa293e7023159b3c7a4c984b6a3480
  0x3ae9d0b74e3968cfcf89a4de4f0d8b2a326a1dfd
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

## portfolio

Show the portfolio for account. Note: the price is not updated in real-time.

```
> portfolio 0xdac17f958d2ee523a2206206994597c13d831ec7       
Total: $1188746.79
Name                            Symbol          Address                                         Price           Balance                 USD                 
Wrapped Ether                   WETH            0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2      3335.56         0.6976344750448605      2327.001649580635   
Tether USD                      USDT            0xdac17f958d2ee523a2206206994597c13d831ec7      1.001           266720.277779           266986.998056779    
BNB                             BNB             0xB8c77482e45F1F44dE1745F52C74426C631bDD52      561.13203671    0.42                    235.6754554182      
USDC                            USDC            0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48      0.998281        195118.248374           194782.84010504506  
stETH                           stETH           0xae7ab96520de3a18e5e111b5eaab095312d7fe84      3362.38         0.03720959512995727     125.11279847306574  
SHIBA INU                       SHIB            0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE      2.68e-05        73323602.02657662       1965.0725343122535  
ChainLink Token                 LINK            0x514910771af9ca656af840dff83e8264ecf986ca      17.66           633.4449161230983       11186.637218733917  
Dai Stablecoin                  DAI             0x6b175474e89094c44da98b954eedeac495271d0f      0.999172        39.887889789776075      39.854862617030136  
Cronos Coin                     CRO             0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b      0.143436        4800000.0               688492.8            
Maker                           MKR             0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2      3764.96         0.008496658437862034    31.989579152213043  
Graph Token                     GRT             0xc944e90c64b2c07662a292be6244bdf05cda44a7      0.353508        63333.33                22388.83882164      
Pepe                            PEPE            0x6982508145454ce325ddbe47a25d4ec3d2311933      7.28e-06        17853165.88             129.9710476064      
Rocket Pool ETH                 rETH            0xae78736cd615f374d3085123a210448e74fc6393      3700.68         0.01459                 53.9929212  
```