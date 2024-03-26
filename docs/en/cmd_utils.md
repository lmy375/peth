# Utilities

## sh (or !)

Run shell commands.
```
peth > sh whoami
user
peth > ! whoami
user
```

## py (or ?)

Evaluate the python code. It can be used as a calculator.

```
peth > py 1 + 2
3
peth > ? 1 + 2
3
peth > ? int(1e18)*100
100000000000000000000
```

## open

Alias to `! open` for opening files or URLs.

```
peth > open https://etherscan.io/
```

## exit

Exit peth console.

```
peth > exit
bye!
```

## ipython

Open an [IPython](https://ipython.readthedocs.io/en/stable/) console, you can directly use `web3`, `eth`, `peth` and `console` in it.

```
peth > ipython
Python 3.10.0 (default, Oct 29 2021, 11:06:42) [Clang 13.0.0 (clang-1300.0.29.3)]
Type 'copyright', 'credits' or 'license' for more information
IPython 7.28.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: eth.block_number
Out[1]: 19515864
```

## time

Timestamp conversion, if the duration in seconds is more than 10 years, it is considered a timestamp. Otherwise, it is considered a time period.

```
peth > timestamp 1651845252
2022-05-06 21:54:12
peth > timestamp 3600
3600 secs
= 1.0 hours
= 0.0 days
```

## int

Format the integer.

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

Calculate Keccak256 hash.
```
peth > keccak256 transfer(address,uint256)
a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
peth > 4byte a9059cbb
transfer(address,uint256)
```


## aes

Perform a simple AES encryption and decryption. Use the md5 of the password as iv.

```
peth > aes enc the_plain_text password
61099fc1a8964f5383b2b64ba9de2225
peth > aes dec 61099fc1a8964f5383b2b64ba9de2225 password
the_plain_text
```