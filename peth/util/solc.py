import solcx

'''

Eg: 

pragma solidity ^0.8.13;

contract Executor {
    constructor() public payable {}

    function run() external returns(address, address, address){
        return (msg.sender, tx.origin, address(this));
    }
}

ETHCALL_CONTRACT will add to the tail. The EthCall contructor code will just
call Executor.run() and return the same return data, which we can decode with
the ABI of Executor.run().
'''

ETHCALL_CONTRACT = '''

contract EthCall {
    constructor() public payable {
        Executor e = new Executor();
        e.run();
        // Just return what run() returned.
        assembly {
            let size := returndatasize()
            returndatacopy(0, 0, size)
            return(0, size)
        }
    }
}
'''

def compile(code):
    return solcx.compile_source(code, output_values=["abi", "bin"])
    # return solcx.compile_source(code, output_values=["abi", "bin"], optimize=True)
    # return solcx.main._compile_combined_json(stdin=code, output_values=["abi", "bin"], optimize=True, via_ir=True)

def compile_with_eth_call(code):
    code += ETHCALL_CONTRACT
    return compile(code)