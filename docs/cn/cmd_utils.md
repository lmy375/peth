# 杂项

## sh (or !)

运行 shell 命令
```
peth > sh whoami
user
peth > ! whoami
user
```

## py (or ?)

解析 python 代码。可以用来当作计算器。

```
peth > py 1 + 2
3
peth > ? 1 + 2
3
peth > ? int(1e18)*100
100000000000000000000
```

## open

相当于 `! open` 用于打开某些文件或网址

```
peth > open https://etherscan.io/
```

## exit

退出 peth console。

```
peth > exit
bye!
```

## ipython

打开 [IPython](https://ipython.readthedocs.io/en/stable/) console，可直接使用 `web3`, `eth`, `peth`, `console` 等对象。

```
peth > ipython
Python 3.10.0 (default, Oct 29 2021, 11:06:42) [Clang 13.0.0 (clang-1300.0.29.3)]
Type 'copyright', 'credits' or 'license' for more information
IPython 7.28.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: eth.block_number
Out[1]: 19515864
```

## time

时间戳转化，如果秒数时长大于10年，则认为是时间戳。否则认为是时间段。

```
peth > timestamp 1651845252
2022-05-06 21:54:12
peth > timestamp 3600
3600 secs
= 1.0 hours
= 0.0 days
```

## int

整数格式化输出。

```
peth > int 100000000000000000000
Value: 100000000000000000000
Value: 1.000000e+20
Value/1e6  (USDT): 100000000000000.0
Value/1e8  (BTC): 1000000000000.0
Value/1e9  (GWei): 100000000000.0
Value/1e18 (Ether): 100.0
Hex: 0x56bc75e2d63100000
Hex(Address): 0x0000000000000000000000056bc75e2d63100000
Hex(Uint256): 0000000000000000000000000000000000000000000000056bc75e2d63100000
```


## keccak256

计算 Keccak256 hash
```
peth > keccak256 transfer(address,uint256)
a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
peth > 4byte a9059cbb
transfer(address,uint256)
```


## aes

进行简单的 AES 加解密。使用密码的 md5 作为 iv。

```
peth > aes enc the_plain_text password
61099fc1a8964f5383b2b64ba9de2225
peth > aes dec 61099fc1a8964f5383b2b64ba9de2225 password
the_plain_text
```