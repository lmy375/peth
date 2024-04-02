// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ArbSys {
    function arbBlockNumber() external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external returns (uint256);
}


struct Transaction {
    address to;
    bytes data;
    uint256 value;
}

struct Context {
    uint256 chainId;
    uint256 blockNumber;
    uint256 timestamp;
    address from;
}

struct Result {
    bool success;
    bytes data;
}

struct TokenBalance {
    address token;
    address user;
    uint256 balance;
}


contract MockSender {

    function getContext() public view returns (Context memory ctx){
        ctx.chainId = block.chainid;
        ctx.from = address(this);
        ctx.timestamp = block.timestamp;
        if (ctx.chainId == 42161){ // arb
            ctx.blockNumber = ArbSys(address(0x64)).arbBlockNumber();
        }else {
            ctx.blockNumber = block.number;
        }
    }

    function execTxs(Transaction[] calldata txs) 
        external payable
        returns (Context memory ctx, Result[] memory results)
    {
        ctx = getContext();
        results = new Result[](txs.length);
        for(uint256 i = 0; i< txs.length; i++){
            (
                results[i].success, 
                results[i].data
            ) = payable(txs[i].to).call{value: txs[i].value}(
                txs[i].data
            );
        }
    }

    TokenBalance[] temp;

    function getBalance(address[] memory tokens, address[] memory users, uint256 minBalanace)
        external
        returns (Context memory ctx, TokenBalance[] memory balances)
    {
        ctx = getContext();
        delete temp;
        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            for (uint256 j = 0; j < users.length; j++) {
                address user = users[j];
                uint256 balance;
                if(token == address(0)){
                    balance = user.balance;
                } else {
                    balance = IERC20(token).balanceOf(user);
                }
                if (balance > minBalanace){
                    temp.push(TokenBalance(token, user, balance));
                }
            }
        }
        balances = temp;
    }
}

contract GetBalanceWrapper {
    constructor(address[] memory tokens, address[] memory users, uint256 minBalanace)
        payable
    {
        MockSender sender = new MockSender();
        sender.getBalance(tokens, users, minBalanace);
        assembly {
            let size := returndatasize()
            returndatacopy(0, 0, size)
            return(0, size)
        }
    }
}

contract ExecTxWrapper {
    constructor(Transaction[] memory txs)
        payable
    {
        MockSender sender = new MockSender();
        sender.execTxs(txs);
        assembly {
            let size := returndatasize()
            returndatacopy(0, 0, size)
            return(0, size)
        }
    }
}
