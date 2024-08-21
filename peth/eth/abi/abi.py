import json
import os
from typing import Dict

from hexbytes import HexBytes

from .abifunc import ABIFunction
from .abitype import ABIType
from .utils import normal_indexes, parse_simple_to_json


class ABI(object):
    def __init__(self, arg: str | list, name: str = "Default") -> None:
        """
        arg:
            - List of ABI item
            - List of simple sigs: "balanceOf(address)->(uin256)"
            - JSON string
            - JSON file path
        """
        self.name = name

        self.raw = arg

        if type(arg) is list:
            if len(arg) > 0:
                if type(arg[0]) is str:
                    self.raw = list(parse_simple_to_json(i) for i in arg)

        elif type(arg) is str:
            if os.path.exists(arg):
                self.raw = json.load(open(arg))
            else:
                try:
                    self.raw = json.loads(arg)
                except json.JSONDecodeError:
                    raise TypeError(f"not valid ABI or file path: {arg}")

        assert type(self.raw) is list, f"Invalid ABI: {arg}"

        self.functions: Dict[str, ABIFunction] = (
            {}
        )  # name => func (without collisions ones)
        self.signatures: Dict[str, ABIFunction] = {}  # sig => func (all functions)
        self.selectors: Dict[bytes, ABIFunction] = (
            {}
        )  # selector => func (all functions)

        self._name_collisions = {}
        for item in self.raw:
            typ = item["type"]
            if typ == "function":
                func = ABIFunction(item)
                self.add_func(func)

    def add_func(self, func: ABIFunction):

        if func.signature in self.signatures:
            # Signatures collision.
            return
        else:
            self.signatures[func.signature] = func

        if func.selector in self.selectors:
            # Selector collision.
            return
        else:
            self.selectors[func.selector] = func

        name = func.name
        if name in self.functions:
            del self.functions[name]
            self._name_collisions[name] = True

        if name not in self._name_collisions:
            self.functions[name] = func

    def merge(self, other: "ABI"):
        self.raw += other.raw
        for func in other.signatures.values():
            self.add_func(func)

    def __getattr__(self, key):
        if key in self.functions:
            return self.functions[key]
        raise KeyError(key)

    def __getitem__(self, key) -> ABIFunction:
        if isinstance(key, bytearray):
            key = bytes(key)
        if key in self.functions:
            return self.functions[key]
        elif key in self.signatures:
            return self.signatures[key]
        elif key in self.selectors:
            return self.selectors[key]
        else:
            try:
                key = bytes(HexBytes(key))
                return self.selectors[key]
            except Exception:
                raise KeyError(key)

    def get_func_abi(self, key) -> ABIFunction:
        try:
            return self[key]
        except KeyError:
            return None

    def _get_function_by_calldata(self, calldata):
        calldata = bytes(HexBytes(calldata))
        assert len(calldata) >= 4, "Calldata too short"

        selector = calldata[:4]
        assert selector in self.selectors, "Selector not found"

        return self.selectors[selector]

    def decode_calldata(self, calldata):
        func = self._get_function_by_calldata(calldata)
        return func.decode_input(calldata)

    def get_type(self, indexes) -> ABIType:
        indexes = normal_indexes(indexes)
        name = indexes[0]
        indexes = indexes[1:]
        func = self[name]
        return func.get_type(indexes)

    def extract_value(self, indexes, values):
        indexes = normal_indexes(indexes)
        name = indexes[0]
        indexes = indexes[1:]
        func = self[name]
        return func.extract_value(indexes, values)

    def extract_value_from_calldata(self, indexes, calldata):
        func = self._get_function_by_calldata(calldata)
        values = func.decode_input(calldata)
        return func.extract_value(indexes, values)

    def explain_calldata(self, pattern: str, calldata, alias: dict = {}) -> list:
        func = self._get_function_by_calldata(calldata)
        return func.explain_calldata(pattern, calldata, alias)

    def map_values(self, calldata) -> list:
        func = self._get_function_by_calldata(calldata)
        values = func.decode_input(calldata)
        return func.map_values(values)

    @classmethod
    def print_value_map(cls, value_map, indent=0):
        for k, v in value_map:
            if type(v) in (tuple, list):
                print(" " * indent, k, ":")
                cls.print_value_map(v, indent + 1)
            else:
                if type(v) is bytes:
                    v = v.hex()
                    if len(v) == 0:
                        v = "0x"

                print(" " * indent, k, ":", v)


ERC20_ABI = ABI(
    [
        "totalSupply() -> (uint256) view",
        "balanceOf(address) -> (uint256) view ",
        "allowance(address, address) -> (uint256) view",
        "name() -> (string) view",
        "symbol() -> (string) view",
        "decimals() -> (uint8) view",
        "transfer(address, uint256) nonpayable",
        "approve(address, uint256) nonpayable",
    ]
)
