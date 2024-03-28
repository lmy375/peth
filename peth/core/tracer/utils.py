from peth.eth.utils import SelectorDatabase

from ..peth import Peth


def get_sig(input: str, online=False):

    if input.startswith("0x"):
        input = input[2:]

    if len(input) >= 8:
        sig = SelectorDatabase.get().get_sig_from_selector(input[:8], True, online)
        if sig is None:
            sig = "0x" + input[:8]
    else:
        sig = "0x" + input

    if sig.find("(") != -1:
        sig = sig[: sig.find("(")]
    return sig + "()"


_erc20_cache = {"eth": "ETH"}


def get_erc20_name(addr, chain="eth"):
    addr = addr.lower()
    if addr not in _erc20_cache:
        peth = Peth.get_or_create(chain)
        ret = peth.call_contract(addr, "symbol()->(string)", silent=True)
        if ret is None:
            ret = "Unknown"
        _erc20_cache[addr] = ret

    return _erc20_cache[addr]


def hex_to_address(value: str):
    """
    Convert '0x0' to '0x0000000000000000000000000000000000000000'
    """
    return "%0#42x" % int(value, 16)


def hex_to_word(value: str):
    """
    Convert '0x0' to '0x0000000000000000000000000000000000000000000000000000000000000000'
    """
    return "%0#66x" % int(value, 16)


def hex_concat(*hex_str: str):
    r = ""
    for s in hex_str:
        if r and s.startswith("0x"):
            s = s[2:]
        r += s
    return r


def hex_contains(a: str, b: str):

    if a.startswith("0x"):  # Remove 0x prefix
        a = a[2:]

    if b.startswith("0x"):
        b = b[2:]

    return b.lower() in a.lower()


def hex_contains_address(a: str, b: str):

    assert b != "0x", "b is empty"
    b = hex_to_address(b)
    return hex_contains(a, b)
