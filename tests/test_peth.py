from peth import Peth
from peth.eth.contract import ERC20

USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


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


def test_get_tokens():
    p = Peth.get_or_create("eth")
    for token, user, balance in p.get_token_balances([USDT, USDC], [USDC, USDT]):
        assert ERC20(p, token).balanceOf(user) == balance


def test_multicall():
    p = Peth.get_or_create("eth")
    usdt = ERC20(p, USDT)
    usdc = ERC20(p, USDC)
    fn = usdt.balanceOf.abi
    txs = [
        (USDT, fn.encode_input([USDT]), 0),
        (USDC, fn.encode_input([USDT]), 0),
    ]
    results = p.multicall_raw(txs)
    status, data = results[0]
    assert status is True
    assert fn.decode_output(data) == usdt.balanceOf(USDT)

    results = p.multicall_raw(txs)
    status, data = results[1]
    assert status is True
    assert fn.decode_output(data) == usdc.balanceOf(USDT)

    results = p.multicall_from(txs, USDC)
    status, data = results[0]
    assert status is True
    assert fn.decode_output(data) == usdt.balanceOf(USDT)

    results = p.multicall_raw(txs)
    status, data = results[1]
    assert status is True
    assert fn.decode_output(data) == usdc.balanceOf(USDT)
