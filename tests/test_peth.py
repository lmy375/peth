from peth import Peth
from peth.eth.contract import ERC20

USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"


def test_call_contract():
    p = Peth.get_or_create("eth")
    s = p.call_contract(USDT, "symbol")
    assert s == "USDT"


def test_contract():
    p = Peth.get_or_create("eth")
    c = p.contract(USDT)

    assert c.symbol() == "USDT"
    assert c["symbol"]() == "USDT"

    c = ERC20(p, USDT)
    assert c.symbol() == "USDT"
    assert c["symbol"]() == "USDT"
