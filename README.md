# Peth

`Peth` is an all-in-one Ethereum SDK and command-line tool, written in Python. It is designed for developers, smart contract auditors, web3 security researchers, and anyone interested in interacting with EVM-compatible chains with ease.

```
➜ peth


     ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄ 
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
    ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░▌       ▐░▌
    ▐░▌       ▐░▌▐░▌               ▐░▌     ▐░▌       ▐░▌
    ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌
    ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░█▀▀▀▀▀▀▀█░▌
    ▐░▌          ▐░▌               ▐░▌     ▐░▌       ▐░▌
    ▐░▌          ▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░▌       ▐░▌
    ▐░▌          ▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌
     ▀            ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀         ▀ 
                                                        

                           -- https://github.com/lmy375

Welcome to the peth shell. Type `help` to list commands.

peth > 
```

Features include:
- An Etherscan-compatible blockchain explorer interface
- ABI encoding/decoding capabilities
- An EVM Bytecode disassembler
- Common DApp contract tools
- And more...

# Documentation

[English](https://peth.readthedocs.io/en/)

[中文](https://peth.readthedocs.io/zh-cn/)

# Installation

From pypi
```
➜ pip install peth
➜ peth
```

From github
```
➜ pip install git+https://github.com/lmy375/peth
➜ peth
```

From source
```
➜ git clone https://github.com/lmy375/peth
➜ cd peth
➜ pip -r requirements.txt
➜ python main.py
```

# Quick Usage

Command-line mode:
```
➜ peth -h
```

Console mode:
```sh
➜ peth
Welcome to the peth shell. Type `help` to list commands.

peth > help

Documented commands (type help <topic>):
========================================
4byte             contract         estimate_gas  name       safe      tx_replay
abi4byte          debank           eth_call      open       send_tx   txs      
abi_decode        debug            exit          oracle     sender    url      
abi_encode        decompile        factory       owner      sh        verify   
address           deth             graph         pair       signer    view     
aes               diff             help          price      status  
aml               diffasm          idm           proxy      storage 
call              disasm           int           proxy_all  time    
chain             download_json    ipython       py         timelock
common_addresses  download_source  keccak256     rpc_call   tx      
config            erc20            log           run        tx_raw  

peth >
```

SDK mode:

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

# Contributing

Help is always appreciated! Feel free to open an issue if you find a problem, or a pull request if you've solved an issue.

Please check out the [Contribution Guide](./docs/en/contribute.md) prior to opening a pull request.


# Buy me a coffee

Send any tokens to [0x2aa75a41805E47eCd94fbBaD84eeF6d1BF21a019](https://debank.com/profile/0x2aa75a41805E47eCd94fbBaD84eeF6d1BF21a019)

# License

This project is licensed under the [AGPL v3](./LICENSE) license.