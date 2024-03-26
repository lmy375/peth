from peth import Peth


def test_call_contract():
    p = Peth.get_or_create("eth")
    s = p.call_contract("0xdAC17F958D2ee523a2206206994597C13D831ec7", "symbol")
    assert s == "USDT"
