import json
import re
from typing import Optional, Dict

import eth_abi

from .utils import func_selector, hex2bytes, collapse_if_tuple


class Signature(object):
    """
    Signature a.k.a ABI item.

    Ref: https://docs.soliditylang.org/en/v0.8.12/abi-spec.html#json
    """


    FUNCTION = "function"
    CONSTRUCTOR = "constructor"
    RECEIVE = "receive"
    FALLBACK = "fallback"
    
    EVENT = "event"
    ERROR = "error"

    PURE = "pure"
    VIEW = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE = "payable"

    def __init__(self):
        # event, error, function, constructor, receive, fallback
        self.type = None

        # Maybe None.
        self.name = None
        self.full_abi = None

        # stateMutability:
        # view, pure, nonpayable, payable
        self.mode = None

        self.selector = None

        self.inputs = []  # [(name, type)] , name can be None.
        self.outputs = []

        # Keep compatibility. Not used now.
        self.constant = None
        self.payable = None
        self.anonymous = None  # For event.

        # For analysis.
        self.modifiers = []

    @property
    def is_function(self) -> bool:
        return self.type in [
            Signature.FUNCTION,
            Signature.CONSTRUCTOR,
            Signature.RECEIVE,
            Signature.FALLBACK
        ]
    
    @property
    def is_event(self) -> bool:
        return self.type in [
            Signature.EVENT,
            Signature.ERROR
        ]

    @property
    def is_view(self) -> bool:
        return self.is_function and self.mode in [
            Signature.VIEW,
            Signature.PURE
        ]

    @property
    def inputs_sig(self) -> str:
        if len(self.inputs) == 0:
            return None
        else:
            return "(%s)" % ",".join(i[1] for i in self.inputs)

    @property
    def outputs_sig(self) -> Optional[str]:
        if len(self.outputs) == 0:
            return None
        else:
            return "(%s)" % ",".join(i[1] for i in self.outputs)

    @property
    def func_sig(self) -> str:
        assert self.is_function, "sig is not a function."
        return "%s(%s)" % (self.name, ",".join(i[1] for i in self.inputs))

    def encode_args(self, args, with_selector=True):
        buf = b''
        if with_selector:
            buf += self.selector
        if self.inputs:
            buf += eth_abi.encode_single(self.inputs_sig, args)
        return buf

    def decode_args(self, data, has_selector=True):
        if type(data) is str:
            data = hex2bytes(data)

        if has_selector:
            selector = data[:4]
            data = data[4:]
            if(selector != self.selector):
                print("[!] selector mismatch: expected %s but get %s" %
                      (self.selector.hex(), selector.hex()))

        if self.inputs:
            return eth_abi.decode_single(self.inputs_sig, data)
        else:
            return None

    def decode_ret(self, data):
        if type(data) is str:
            data = hex2bytes(data)
        
        if self.outputs:
            ret_values = eth_abi.decode_single(self.outputs_sig, data)
            if len(ret_values) == 1:
                return ret_values[0]
            else:
                return ret_values
        else:
            return None

    def __str__(self) -> str:
        buf = ''

        if self.is_function:
            buf += '0x' + self.selector.hex() + ' '

        if self.type:
            buf += self.type + ' '

        if self.name:
            buf += self.name

        buf += "("
        buf += ", ".join("%s%s" % (typ, ' ' + name if name else "")
                         for name, typ in self.inputs)
        buf += ")"

        if self.mode and self.mode != Signature.NONPAYABLE:
            buf += " " + self.mode

        if self.outputs:
            buf += " returns ("   
            buf += ", ".join("%s%s" % (typ, ' ' + name if name else "")
                         for name, typ in self.outputs)
            buf += ")"

        return buf

    @classmethod
    def split_sig(cls, sig: str) -> list:
        sig = re.sub(r"\s", "", sig)  # remove blank chars.
        if sig.startswith('(') and sig.endswith(')'):
            sig = sig[1:-1] # Remove ()

        types = []
        left = 0

        type_str = ''
        for c in sig:
            if c == ',' and left == 0:
                types.append(type_str)
                type_str = ''
                continue

            elif c == '(':
                left += 1

            elif c == ')':
                left -= 1
                assert left >= 0, "Invalid sig: %s" % sig
            
            type_str += c

        if type_str:
            types.append(type_str) # Append the last one.

        return types

    @classmethod
    def from_sig(cls, sig: str) -> "Signature":
        """
        Function like: name(typ1,typ2)->(typ3)
        """
        s = cls()

        # Only view funtion.
        s.type = Signature.FUNCTION

        sig = re.sub(r"\s", "", sig)  # remove blank chars.
        sigs = sig.split("->")
        func_sig = sigs[0]

        s.selector = func_selector(func_sig)

        idx = func_sig.index("(")
        s.name = func_sig[:idx]  # Function name.

        args_sig = func_sig[idx:]
        for i in cls.split_sig(args_sig):
            s.inputs.append((None, i))

        if len(sigs) == 2:
            return_sig = sigs[1]
            for i in cls.split_sig(return_sig):
                s.outputs.append((None, i))
        return s

    @classmethod
    def from_abi(cls, item: Dict) -> "Signature":

        sig = cls()
        sig.full_abi = item
        sig.type = item["type"]

        # Use .get as value can be None
        sig.name = item.get("name")
        sig.constant = item.get("constant")
        sig.payable = item.get("payable")
        sig.anonymous = item.get("anonymous")
        sig.mode = item.get("stateMutability")

        for arg in item.get("inputs", []):
            sig.inputs.append((arg["name"], collapse_if_tuple(arg)))

       
        for arg in item.get("outputs", []):
            sig.outputs.append((arg["name"], collapse_if_tuple(arg)))

        if sig.type == Signature.FUNCTION:
            sig.selector = func_selector(sig.func_sig)

        return sig


class Signatures(object):
    def __init__(self, human_abi_or_json_abi=None) -> None:
        self.sigs = []
        self.name_map = {}
        self.selector_map = {}

        if human_abi_or_json_abi:
            self.update(human_abi_or_json_abi)

    def add_sig(self, s: Signature):
        self.sigs.append(s)
        self.name_map[s.name] = s
        self.selector_map[s.selector] = s

    def update(self, abi_list):
        if type(abi_list) is str:
            abi_list = json.loads(abi_list)

        assert type(
            abi_list) is list, "JSON ABI or human-readable ABI list needed."

        for item in abi_list:
            if type(item) is str:  # human-readable ABI
                s = Signature.from_sig(item)
                self.add_sig(s)

            elif type(item) is dict:  # Classic JSON ABI.
                if item["type"] == "function":
                    s = Signature.from_abi(item)
                    self.add_sig(s)

    def find_by_name(self, name):
        return self.name_map.get(name)

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
