import json
import re

from utils import func_selector


class Signature(object):
    def __init__(self):
        self.name = None
        self.selector = None
        self.type = None  # Only "function" supported now. TODO: add event.
        self.sig = None
        self.args_sig = None
        self.return_sig = None

    @classmethod
    def from_sig(cls, sig):
        sig = re.sub(r"\s", "", sig)  # remove blank chars.

        sigs = sig.split("->")
        func_sig = sigs[0]
        selector = func_selector(func_sig)

        idx = func_sig.index("(")
        func_name = func_sig[:idx]
        args_sig = func_sig[idx:]

        if len(sigs) == 1:
            return_sig = None
        else:
            assert len(sigs) == 2
            return_sig = sigs[1]

        s = cls()
        s.sig = sig
        s.selector = selector
        s.name = func_name
        s.type = "function"
        s.args_sig = args_sig
        s.return_sig = return_sig
        return s

    @classmethod
    def from_abi(cls, item):
        name = item["name"]
        args_sig = ",".join(i["type"] for i in item["inputs"])
        return_sig = ",".join(i["type"] for i in item["outputs"])
        sig = f"{name}({args_sig})->({return_sig})"
        return cls.from_sig(sig)


class Signatures(object):
    def __init__(self, human_abi_or_json_abi=None) -> None:
        self.sig_map = {}
        self.name_map = {}
        self.selector_map = {}

        if human_abi_or_json_abi:
            self.update(human_abi_or_json_abi)

    def add_sig(self, s):
        self.sig_map[s.sig] = s
        self.name_map[s.name] = s
        self.selector_map[s.selector] = s

    def iter_sig(self):
        return self.sig_map.values()

    def update(self, abi):
        if type(abi) is str:
            abi = json.loads(abi)

        assert type(abi) is list, "JSON ABI or human-readable ABI needed."

        for item in abi:
            if type(item) is str:  # human-readable ABI
                s = Signature.from_sig(item)
                self.add_sig(s)

            elif type(item) is dict:  # Classic JSON ABI.
                if item["type"] == "function":
                    s = Signature.from_abi(item)
                    self.add_sig(s)

    def find_by_name(self, name):
        return self.name_map.get(name)

    def find_by_sig(self, sig):
        sig = re.sub(r"\s", "", sig)  # remove blank chars.
        return self.sig_map.get(sig)

    def find_by_selector(self, selector):
        return self.selector_map.get(bytes(selector))


ERC20Signatures = Signatures(
    [
        "totalSupply() -> (uint256)",
        "balanceOf(address) -> (uint256)",
        "allowance(address, address) -> (uint256)",
        "name() -> (string)",
        "symbol() -> (string)",
        "decimals() -> (uint8)",
    ]
)

UniswapV2PairSignatures = Signatures(
    [
        "getReserves() -> (uint112, uint112, uint32)"
    ]
)
