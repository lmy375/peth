from web3 import Web3

from peth import Peth
from peth.eth.evm.chain import Chain
from peth.eth.evm.contract import ERC20, Contract
from peth.eth.evm.forkchain import ForkChain


def test_uniswap():

    chain = Chain(ForkChain.fork("eth", 13939311))

    # Uniswap ETH/USDT LP (UNI-V2)
    addr = "0x0D4A11D5EEAAC28EC3F61D100DAF4D40471F1852"
    account = chain.ensure_account(addr)
    assert account.remote
    assert account.code[:4] == b"\x60\x80\x60\x40"
    assert chain.get_storage(addr, 0) == 736442483871157941

    uni_pair = Contract(
        addr,
        [
            "totalSupply()->(uint)",
            "name() -> (string)",
            "getReserves() -> (uint112, uint112)",
        ],
        chain=chain,
    )
    assert uni_pair.totalSupply.call() == 736442483871157941
    assert uni_pair.name.call() == "Uniswap V2"
    assert uni_pair.getReserves.call() == (22602912058312919637977, 86801913269391)


def test_xsnx():
    chain = Chain(ForkChain.fork("eth", 12419917))

    xSNX = Contract(
        "0x2367012AB9C3DA91290F71590D5CE217721EEFE4",
        ["mint(uint256) payable", "balanceOf(address)->(uint) view"],
        chain=chain,
    )

    r = xSNX.mint(0, value=Web3.to_wei(10, "ether"))
    assert r.success
    assert xSNX.balanceOf(chain.attacker) == 0x02FE241367B60954C998


def test_weth():
    weth_addr = "0xC02AAA39B223FE8D0A0E5C4F27EAD9083C756CC2"
    chain = Chain(ForkChain.fork("eth", 12419917))
    weth = Contract(
        weth_addr, Peth.get_or_create("eth").scan.get_abi(weth_addr), chain=chain
    )
    assert weth.symbol() == "WETH"
    assert weth.name() == "Wrapped Ether"
    assert weth.balanceOf(weth_addr) == 75024649058215338010


def test_enum_uni_pairs():
    chain = Chain(ForkChain.fork("eth", 14048340))  # 2021/01/21
    chain.use_as_default()

    p = Peth.get_or_create("eth")

    UniswapV2Factory = Contract(
        "0x5C69BEE701EF814A2B6A3EDD4B1652CB9CC5AA6F",
        p.scan.get_abi("0x5C69BEE701EF814A2B6A3EDD4B1652CB9CC5AA6F"),
    )
    UniswapV2PairABI = p.scan.get_abi("0xB4E16D0168E52D35CACD2C6185B44281EC28C9DC")

    total = UniswapV2Factory.allPairsLength()
    assert total == 61616
    for i in range(total):
        if i > 5:
            break
        lp = UniswapV2Factory.allPairs(i)
        lp = Contract(lp, UniswapV2PairABI)
        token0 = ERC20(lp.token0())
        token1 = ERC20(lp.token1())
        print(token0.symbol(), token1.symbol())

        if i == 0:
            assert ("USDC", "WETH") == (token0.symbol(), token1.symbol())
        elif i == 1:
            assert ("USDP", "USDC") == (token0.symbol(), token1.symbol())
        elif i == 2:
            assert ("CHAI", "WETH") == (token0.symbol(), token1.symbol())
        elif i == 3:
            assert ("DAI", "WETH") == (token0.symbol(), token1.symbol())
        elif i == 4:
            assert ("REN", "USDC") == (token0.symbol(), token1.symbol())
        elif i == 5:
            assert ("DAI", "USDC") == (token0.symbol(), token1.symbol())

    Chain.default = None
