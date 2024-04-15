from typing import List, Union

from eth_hash.auto import keccak
from hexbytes import HexBytes

from .abitype import ABIType
from .utils import (
    abi_decode,
    abi_encode,
    get_item_by_index,
    get_item_value_by_index,
    normal_indexes,
    parse_simple_to_json,
)


class ExtProcessor(object):
    SEP_MARKER = ":"

    def process(self, func: "ABIFunction", key: str, values) -> str:
        return str(func.extract_value(key, values))


class ABIFunction(object):
    def __init__(self, raw: Union[dict, str]) -> None:
        """
        raw: type string or full json.
        """
        if type(raw) is str:
            raw = parse_simple_to_json(raw)

        self.raw = raw

        self.name = self.raw["name"]
        self.func_type = self.raw["stateMutability"]

        self.inputs: List[ABIType] = []
        for item in self.raw["inputs"]:
            self.inputs.append(ABIType(raw=item))

        self.outputs: List[ABIType] = []
        for item in self.raw["outputs"]:
            self.outputs.append(ABIType(raw=item))

    @property
    def is_view(self):
        return self.func_type in ["view", "pure"]

    @property
    def is_payable(self):
        return self.func_type == "payable"

    @property
    def full(self):
        s = f"function {self.name}("
        s += ", ".join(str(i) for i in self.inputs)
        s += f") {self.func_type} returns ("
        s += ", ".join(str(i) for i in self.outputs)
        s += ")"
        return s

    @property
    def simple(self):
        return f"{self.signature}->{self.output_type_str} {self.func_type}"

    @property
    def input_types(self):
        return [i.type_str for i in self.inputs]

    @property
    def input_type_str(self):
        s = "("
        s += ",".join(self.input_types)
        s += ")"
        return s

    @property
    def output_types(self):
        return [i.type_str for i in self.outputs]

    @property
    def output_type_str(self):
        s = "("
        s += ",".join(self.output_types)
        s += ")"
        return s

    @property
    def signature(self):
        return f"{self.name}{self.input_type_str}"

    @property
    def selector(self) -> bytes:
        return HexBytes(keccak(self.signature.encode())[:4])

    def __repr__(self):
        return self.full

    def encode_input(self, args=[], include_selector=True) -> HexBytes:
        calldata = HexBytes(abi_encode(self.input_types, args))
        if include_selector:
            calldata = HexBytes(self.selector) + calldata
        return HexBytes(calldata)

    def decode_input(self, calldata):
        calldata = HexBytes(calldata)
        assert (
            calldata[0:4] == self.selector
        ), f"selector not match: {calldata[0:4]} {self.selector}"
        calldata = calldata[4:]
        return abi_decode(self.input_types, calldata)

    def encode_output(self, rets=[], auto_tuple=True) -> HexBytes:
        if auto_tuple and len(self.outputs) == 1:
            rets = [rets]
        return HexBytes(abi_encode(self.output_types, rets))

    def decode_output(self, retdata, auto_one=True):
        if len(self.outputs) == 0:
            # If no output type, return the entire bytes.
            return retdata

        ret = abi_decode(self.output_types, HexBytes(retdata))
        if auto_one and len(self.outputs) == 1:
            return ret[0]
        return ret

    def get_static_offset(self, name):
        static_offset = 0
        for arg in self.inputs:
            if arg.name == name:
                return static_offset
            static_offset += arg.static_size
        raise (NameError(f"{name} not in arguments of {self}"))

    def get_type(self, indexes="") -> ABIType:
        indexes = normal_indexes(indexes)

        # Skip function name if provided in indexes.
        if indexes[0] == self.name:
            indexes = indexes[1:]

        arg = get_item_by_index(indexes[0], self.inputs)
        return arg.get_type(indexes[1:])

    def extract_value(self, indexes="", values=[]):
        assert len(values) == len(self.inputs), "Value not match arguments size"

        indexes = normal_indexes(indexes)

        # Skip function name if provided in indexes.
        if indexes[0] == self.name:
            indexes = indexes[1:]

        arg, value = get_item_value_by_index(indexes[0], self.inputs, values)
        return arg.extract_value(indexes[1:], value)

    def extract_calldata(self, indexes, calldata):
        values = self.decode_input(calldata)
        return self.extract_value(indexes, values)

    def map_values(self, values):
        assert len(values) == len(self.inputs), "Value not match arguments size"

        r = []
        for arg, value in zip(self.inputs, values):
            r.append(arg.map_values(value))
        return r

    def explain_calldata(self, pattern: str, calldata, ext: ExtProcessor = None) -> str:
        """
        Pattern:
            Some words {{key}} some words {{key:hint_for_ext_processor}} some words.
        """
        START_MARKER = "{{"
        END_MARKER = "}}"

        values = self.decode_input(calldata)
        r = []
        while True:
            start = pattern.find(START_MARKER)
            if start == -1:
                r.append(pattern)
                return "".join(str(i) for i in r)

            r.append(pattern[:start])
            end = pattern.find(END_MARKER)
            assert end != -1, "Unclosed marker"
            key = pattern[start + len(START_MARKER) : end]

            try:
                if ext:
                    # Yield to ext-processor.
                    value = ext.process(self, key, values)
                else:
                    key = key.split(ExtProcessor.SEP_MARKER)[0]
                    value = self.extract_value(key, values)
            except Exception as e:
                print(f"[*] Error in explain_calldata, key={key}: {e}")
                # Unable to resolve the key, just return itself.
                value = "{{%s}}" % key

            r.append(value)
            pattern = pattern[end + len(END_MARKER) :]
