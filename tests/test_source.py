from peth.core.peth import Peth

import solcx


def test_get_source():
    # peth = Peth.get_or_create('ethcn')
    # srcs = peth.scan.get_source(
    #     '0x554ee3d9ed7E9ec21E186c7dd636430669812f73', False)

    peth = Peth.get_or_create('avax')
    srcs = peth.scan.get_source(
        '0x77777777777d4554c39223C354A05825b2E8Faa3', False)    
        
    sources = {}
    for name, content in srcs.items():
        sources[name] = {"content": content}

    input_json = {
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "outputSelection": {
                "*": {
                    "": [
                        "ast"
                    ]
                }
            }
        }
    }
    solcx.install_solc('0.6.11')
    output = solcx.compile_standard(input_json, solc_version="0.6.11")
    print(output["sources"]["IERC20.sol"]["ast"])
