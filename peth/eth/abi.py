import json
import os
import warnings
import re
from typing import Dict, List

import eth_abi
from eth_hash.auto import keccak
from hexbytes import HexBytes

ALIGN_SIZE = 32
DYNAMIC_SIZE = -1

def _normal_indexes(indexes):
    if type(indexes) is str:
        indexes = indexes.replace("[", ".").replace("]", "")
        indexes = indexes.split(".")
        indexes = list(filter(None, indexes))  # Remove ""
    assert type(indexes) is list, "Invalid indexes"
    return indexes

def _split_sig(sig: str) -> list:
    sig = re.sub(r"\s", "", sig)  # remove blank chars.
    assert sig.startswith('(') and sig.endswith(')'), f"Invalid sig: {sig}"
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

def _convert_typ_to_abi_item(type_str):
    if not type_str.startswith("("):
        return {
            "name": "",
            "type": type_str,
            "internalType": type_str
        }
    
    typ = "tuple"
    if type_str.endswith(']'):
        i = type_str.rindex(')') + 1
        typ += type_str[i:]
        type_str = type_str[:i]

    a = {
        "name": "",
        "components": [],
        "type": typ,
        "internalType": typ
    }

    i = 0
    for elem_type in _split_sig(type_str):
        item = _convert_typ_to_abi_item(elem_type)
        item["name"] = "elem%s" % i
        a["components"].append(item)
        i += 1
    return a


def _parse_simple_to_json(sig):
    """
    "balanceOf(address)->(uin256)"
    =>
    {
        "name": "balanceOf",
        "inputs": [{
            "type": "address",
            "name": "arg0"
        }],
        "outputs": [{
            "type": "uint256",
            "name": ""
        }]
    }
    """
    a = {
        "type": "function",
        "name": "",
        "inputs": [],
        "outputs": [],

        # Default values as simple sig does not cover.
        "constant": False,
        "payable": False,
        "stateMutability": "nonpayable",
    }

    sig = re.sub(r"\s", "", sig)  # remove blank chars.
    sigs = sig.split("->")
    func_sig = sigs[0]

    idx = func_sig.index("(")
    a["name"] = func_sig[:idx]  # Function name.

    i = 0
    args_sig = func_sig[idx:]
    for arg_type in _split_sig(args_sig):
        item = _convert_typ_to_abi_item(arg_type)
        item["name"] =  "arg%s" % i
        a["inputs"].append(item)
        i += 1

    if len(sigs) == 2:
        return_sig = sigs[1]
        for ret_type in _split_sig(return_sig):
            item = _convert_typ_to_abi_item(ret_type)
            a["outputs"].append(item)
    return a

class ExtProcessor(object):

    SEP_MARKER = ":"

    def process(self, func: 'ABIFunction', key: str, values) -> str:
        return str(func.extract_value(key, values))

class ABIArgument(object):

    def __init__(self, name=None, typ=None, components=None, raw=None) -> None:
        assert raw is not None or typ is not None
        assert raw is None or type(raw) is dict, "Invalid raw"
        assert typ is None or type(typ) is str, "Invalid typ"

        if raw is None:
            raw = _convert_typ_to_abi_item(typ)

        self.raw = raw
        self.type = raw["type"]
        self.name = name if name else raw["name"]

        if components:
            self.components: List[ABIArgument] = components
        else:
            self.components: List[ABIArgument] = []
            if raw:
                for item in raw.get("components", []):
                    self.components.append(ABIArgument(raw=item))

        if self.type.startswith("tuple"):
            self.is_tuple = True
            assert len(self.components) > 0
        else:
            self.is_tuple = False
            assert len(self.components) == 0

        if self.type.endswith("]"):
            self.is_array = True
            if self.type.endswith("[]"):
                self.base_type = ABIArgument(self.name, self.type[:-2], self.components)
                self.is_dynamic_array = True
                self.array_size = DYNAMIC_SIZE
            else:
                start = typ.rindex("[")
                end = -1
                size = int(typ[start + 1 : end])

                self.base_type = ABIArgument(self.name, self.type[:start], self.components)
                self.is_dynamic_array = False
                self.array_size = size
        else:
            self.is_array = False
            self.base_type = None
            self.is_dynamic_array = False
            self.array_size = None

        self._is_dynamic = None

    @property
    def type_str(self) -> str:
        if self.is_tuple:
            s = "("
            s += ",".join(str(i.type) for i in self.components)
            s += ")"
            assert self.type.startswith("tuple")
            s += self.type.strip("tuple")
            return s
        else:
            return self.type

    @property
    def is_dynamic(self) -> bool:
        if self._is_dynamic is not None:
            return self._is_dynamic

        if self.is_array:
            if self.is_dynamic_array:
                self._is_dynamic = True
            else:
                self._is_dynamic = self.base_type.is_dynamic
            return self._is_dynamic

        if self.is_tuple:
            for item in self.components:
                if item.is_dynamic:
                    self._is_dynamic = True
                    return True

        # not array, not tuple
        self._is_dynamic = self.type in ["bytes", "string"]
        return self._is_dynamic

    @property
    def static_size(self) -> int:
        if self.is_dynamic:
            return ALIGN_SIZE

        if self.is_array:
            assert not self.is_dynamic_array
            return self.base_type.static_size * self.array_size

        if self.is_tuple:  # static tuple
            return sum(i.static_size for i in self.components)

        # basic type.
        return ALIGN_SIZE

    @property
    def element_type(self) -> str:
        s = self
        while s.base_type is not None:
            s = s.base_type
        return s.type

    def __repr__(self):
        return f"{self.type_str} {self.name}"

    def tuple_get_static_offset(self, name):
        assert self.is_tuple

        static_offset = 0
        for arg in self.components:
            if arg.name == name:
                return static_offset
            static_offset += arg.static_size
        raise (NameError(f"{name} not in tuple of {self}"))

    def extract_value(self, indexes="", values=None):
        """
        Extract the value with the indexes path.
        """
        indexes = _normal_indexes(indexes)
        assert eth_abi.is_encodable(self.type_str, values), "Value not match type"

        if len(indexes) == 0:
            # Return the entire value
            return values

        elif self.is_array:
            assert type(values) in (list, tuple), "Value not array"
            if indexes[0] == "length":
                # Array length
                return len(values)
            else:
                # Get array element
                i = int(indexes[0])
                if i < 0:
                    i = len(values) + i

                assert i >= 0 and i < len(values), "Value array out-of-bound"
                return self.base_type.extract_value(indexes[1:], values[i])

        elif self.is_tuple:
            assert type(values) in (list, tuple), "Value not tuple"
            assert len(values) == len(self.components), "Value not match tuple size"

            name = indexes[0]

            try:
                i = int(name)
                assert i < len(values), "Value tuple out-of-bound"
                arg = self.components[i]
                return arg.extract_value(indexes[1:], values[i])
            except ValueError:
                pass

            for i, arg in enumerate(self.components):
                if arg.name == name:
                    return arg.extract_value(indexes[1:], values[i])

            raise ValueError(f"{name} not in tuple {self}")

        else:
            # string/bytes .length
            assert self.type in ["bytes", "string"], "Should be bytes/string length"
            assert indexes[0] == "length", "Should be length here"
            assert len(indexes) == 1, "length should be end of indexes"
            assert type(values) in (bytes, str)
            return len(values)

    def map_values(self, values):
        """
        foo(uint256 a, uint256 b, (uint256 e) c)
        (1, 2, (3,))
        =>
        [
            ("a", 1),
            ("b", 2),
            ("c", (
                ("e", 3),
            ))
        ]
        """
        if self.is_array:
            assert type(values) in (list, tuple), "Value not array"
            r = []
            for i, v in enumerate(values):
                name = f"[{i}]"
                _, v = self.base_type.map_values(values[i])
                r.append((name, v))
            return (self.name, r)
        
        elif self.is_tuple:
            assert type(values) in (list, tuple), "Value not tuple"
            assert len(values) == len(self.components), "Value not match tuple size"

            r = []
            for i, arg in enumerate(self.components):
                name = f"{arg.name}"
                _, v = arg.map_values(values[i])  
                r.append((name, v))
            return (self.name, r)
        else:
            return (self.name, values)         

class ABIFunction(object):

    def __init__(self, raw: dict) -> None:
        """
        raw: type string or full json.
        """
        if type(raw) is str:
            raw = _parse_simple_to_json(raw)

        self.raw = raw

        self.name = self.raw["name"]

        self.inputs: List[ABIArgument] = []
        for item in self.raw["inputs"]:
            self.inputs.append(ABIArgument(raw=item))

        self.outputs: List[ABIArgument] = []
        for item in self.raw["outputs"]:
            self.outputs.append(ABIArgument(raw=item))

    @property
    def is_view(self):
        return self.raw["stateMutability"] in ["view", "pure"]

    @property
    def full(self):
        s = f"function {self.name}("
        s += ", ".join(str(i) for i in self.inputs)
        s += ") returns ("
        s += ", ".join(str(i) for i in self.outputs)
        s += ")"
        return s

    @property
    def simple(self):
        return f"{self.signature}->{self.output_type_str}"

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
    
    def encode_input(self, args=[]):
        return HexBytes(self.selector + HexBytes(eth_abi.encode(self.input_types, args)))

    def decode_input(self, calldata):
        calldata = HexBytes(calldata)
        assert calldata[0:4] == self.selector, "select not match"
        calldata = calldata[4:]
        return eth_abi.decode(self.input_types, calldata)

    def encode_output(self, rets=[]):
        return HexBytes(eth_abi.encode(self.output_types, rets))

    def decode_output(self, retdata):
        return eth_abi.decode(self.output_types, retdata)

    def get_static_offset(self, name):
        static_offset = 0
        for arg in self.inputs:
            if arg.name == name:
                return static_offset
            static_offset += arg.static_size
        raise (NameError(f"{name} not in arguments of {self}"))

    def extract_value(self, indexes="", values=[]):
        assert len(values) == len(self.inputs), "Value not match arguments size"

        indexes = _normal_indexes(indexes)
        if indexes[0] == self.name:
            indexes = indexes[1:]

        name = indexes[0]

        try:
            i = int(name)
            assert i < len(values), "Value tuple out-of-bound"
            arg = self.inputs[i]
            return arg.extract_value(indexes[1:], values[i])
        except ValueError:
            pass

        for i, arg in enumerate(self.inputs):
            if arg.name == name:
                return arg.extract_value(indexes[1:], values[i])

        raise ValueError(f"unknown arguments {indexes}")
    
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
                return ''.join(str(i) for i in r)
            
            r.append(pattern[:start])
            end = pattern.find(END_MARKER)
            assert end != -1, "Unclosed marker"
            key = pattern[start + len(START_MARKER): end]

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
                value = '{{%s}}' % key

            r.append(value)
            pattern = pattern[end + len(END_MARKER):]
        
class ABI(object):

    def __init__(self, arg) -> None:
        """
        arg: 
            - List of ABI item
            - List of simple sigs: "balanceOf(address)->(uin256)"
            - JSON string
            - JSON file path
        """
        if type(arg) is list:
            self.raw = arg
            if len(arg) > 0:
                if type(arg[0]) is str:
                    self.raw = list(_parse_simple_to_json(i) for i in arg)

        elif type(arg) is str:
            if os.path.exists(arg):
                self.raw = json.load(open(arg))
            else:
                try:
                    self.raw = json.loads(arg)
                except json.JSONDecodeError:
                    raise TypeError(f"not valid ABI or file path: {arg}")

            assert type(self.raw) is list, "Invalid ABI."

        self.functions: Dict[
            str, ABIFunction
        ] = {}  # name => func (without collisions ones)
        self.signatures: Dict[str, ABIFunction] = {}  # sig => func (all functions)
        self.selectors: Dict[
            bytes, ABIFunction
        ] = {}  # selector => func (all functions)

        self._name_collisions = {}
        for item in self.raw:
            typ = item["type"]
            if typ == "function":
                func = ABIFunction(item)
                self.add_func(func)

    def add_func(self, func: ABIFunction):
        name = func.name

        assert func.signature not in self.signatures, "Signatures collision."
        self.signatures[func.signature] = func

        assert func.selector not in self.selectors, "Selector collision."
        self.selectors[func.selector] = func

        if name in self.functions:
            del self.functions[name]
            self._name_collisions[name] = True

        if name not in self._name_collisions:
            self.functions[name] = func
    
    def merge(self, other: 'ABI'):
        self.raw += other.raw
        for func in other.signatures.values():
            self.add_func(func)

    def __getattr__(self, key):
        if key in self.functions:
            return self.functions[key]
        else:
            return super().__getattr__(key)

    def __getitem__(self, key):
        if key in self.functions:
            return self.functions[key]
        elif key in self.signatures:
            return self.signatures[key]
        elif key in self.selectors:
            return self.selectors[key]
        else:
            return super().__getitem__(key)

    def _get_function_by_calldata(self, calldata):
        calldata = bytes(HexBytes(calldata))
        assert len(calldata) >= 4, "Calldata too short"

        selector = calldata[:4]
        assert selector in self.selectors, "Selector not found"

        return self.selectors[selector]
    
    def decode_calldata(self, calldata):
        func = self._get_function_by_calldata(calldata)
        return func.decode_input(calldata)
    
    def extract_value(self, indexes, values):
        indexes = _normal_indexes(indexes)
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
                print(' ' * indent, k, ":")
                cls.print_value_map(v, indent+1)
            else:
                if type(v) is bytes:
                    v = v.hex()
                    if len(v) == 0:
                        v = "0x"

                print(' ' * indent, k, ":", v)

