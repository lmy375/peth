# 使用

## 命令行

直接通过命令行进行调用。

```sh
$ peth -c eth --cmd erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7
Name: Tether USD
Symbol: USDT
decimals: 6
totalSupply: 48999156520373530
```

查看完整命令行选项
```sh
$ peth -h
```

## 控制台

进入 peth 控制台。

```
Welcome to the peth shell. Type `help` to list commands.

peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7
Name: Tether USD
Symbol: USDT
decimals: 6
totalSupply: 48999156520373530
```

控制台中的命令均可以通过 `peth --cmd` 通过命令行调用。

## 脚本

通过脚本使用 peth python 库，示例：

```sh
➜ ipython
Python 3.10.0 (default, Oct 29 2021, 11:06:42) [Clang 13.0.0 (clang-1300.0.29.3)]
Type 'copyright', 'credits' or 'license' for more information
IPython 7.28.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from peth import Peth

In [2]: p = Peth.get_or_create('eth')

In [3]: p.call_contract('0xdAC17F958D2ee523a2206206994597C13D831ec7', 'name')
Out[3]: 'Tether USD'

In [4]: p.call_contract('0xdAC17F958D2ee523a2206206994597C13D831ec7', 'name()->(string)')
Out[4]: 'Tether USD'
```

