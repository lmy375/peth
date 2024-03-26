=======
Peth
=======

Peth 是一款由 Python 语言开发的 Ethereum SDK 及脚本工具，为智能合约开发者，安全研究者，合约审计等日常需要与各种 EVM 链、智能合约交互的用户服务。

.. code-block::
    
        _________   _...._            __.....__                .
        \        |.'      '-.     .-''         '.            .'|
         \        .'```'.    '.  /     .-''"'-.  `.      .| <  |
          \      |       \     \/     /________\   \   .' |_ | |
           |     |        |    ||                  | .'     || | .'''-.
           |      \      /    . \    .-------------''--.  .-'| |/.'''. \
           |     |\`'-.-'   .'   \    '-.____...---.   |  |  |  /    | |
           |     | '-....-'`      `.             .'    |  |  | |     | |
          .'     '.                 `''-...... -'      |  '.'| |     | |
        '-----------'                                  |   / | '.    | '.
                                                      `'-'  '---'   '---'
    
    
                               -- https://github.com/lmy375
    
    Welcome to the peth shell. Type `help` to list commands.
    
    peth > help
    
    Documented commands (type help <topic>):
    ========================================
    abi4byte          debank           exit     open       sender     verify
    abi_encode        debug            factory  oracle     sh         view
    aes               decompile        gnosis   owner      sha3
    aml               deth             graph    pair       sig
    balance           diff             help     price      signer
    bye               diffasm          idm      proxy      storage
    calldata_decode   disasm           int      proxy_all  timelock
    chain             download_json    ipython  py         timestamp
    code              download_source  log      quit       tx
    codesize          erc20            loop     rpc_call   tx_raw
    common_addresses  estimate_gas     name     run        tx_replay
    config            eth_call         nonce    safe       txs
    contract          eth_call_raw     number   send_tx    url

.. toctree::
    :caption: 概述
    :maxdepth: 2

    install.md
    usage.md

.. toctree::
    :caption: 命令
    :maxdepth: 2

    cmd_eth.md
    cmd_dapp.md
    cmd_abi.md
    cmd_source.md
    cmd_bytecode.md
    cmd_tx.md
    cmd_conf.md
    cmd_utils.md

.. toctree::
    :caption: 其他
    :maxdepth: 2

    contributing.md

