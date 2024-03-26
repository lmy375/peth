# Usage

## Command Line

Execute directly with the `peth` command line.

```sh
$ peth -c eth --cmd erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7
Name: Tether USD
Symbol: USDT
decimals: 6
totalSupply: 48999156520373530
```

View the complete command line options
```sh
$ peth -h
```

## Console

Enter the `peth` console.
```
Welcome to the peth shell. Type `help` to list commands.

peth > erc20 0xdAC17F958D2ee523a2206206994597C13D831ec7
Name: Tether USD
Symbol: USDT
decimals: 6
totalSupply: 48999156520373530
```

Commands in the console can be invoked through the command line using `peth --cmd`.

You can view command help by using the `help` command.

```
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

peth > help erc20

        erc20 <address> : print ERC20 information.
        erc20 <address> <function> <args> : call ERC20 function.
```

## Script

Use `peth` as a python library through a script, example:

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

