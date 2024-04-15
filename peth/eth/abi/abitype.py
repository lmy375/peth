import ast
import re
from typing import List

from hexbytes import HexBytes

from .utils import (
    convert_typ_to_abi_item,
    eth_abi,
    get_item_by_index,
    get_item_value_by_index,
    normal_indexes,
)

ALIGN_SIZE = 32
DYNAMIC_SIZE = -1


class ABIType(object):
    def __init__(self, name="", typ=None, components=None, raw=None) -> None:
        assert raw is not None or typ is not None
        assert raw is None or type(raw) is dict, "Invalid raw"
        assert typ is None or type(typ) is str, "Invalid typ"

        if raw is None:
            raw = convert_typ_to_abi_item(typ)

        self.raw = raw
        self.type = raw["type"]
        self.name = name if name else raw["name"]

        if components:
            self.components: List[ABIType] = components
        else:
            self.components: List[ABIType] = []
            if raw:
                for item in raw.get("components", []):
                    self.components.append(ABIType(raw=item))

        if self.type.startswith("tuple"):
            self.is_tuple = True
            assert len(self.components) > 0
        else:
            self.is_tuple = False
            assert len(self.components) == 0

        if self.type.endswith("]"):
            self.is_array = True
            if self.type.endswith("[]"):
                self.base_type = ABIType(self.name, self.type[:-2], self.components)
                self.is_dynamic_array = True
                self.array_size = DYNAMIC_SIZE
            else:
                start = self.type.rindex("[")
                end = -1
                size = int(self.type[start + 1 : end])

                self.base_type = ABIType(self.name, self.type[:start], self.components)
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
            s += ",".join(i.type_str for i in self.components)
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
    def is_basic(self):
        return not self.is_array and not self.is_tuple

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
        """
        Return the basic element type of multi-dim array.
        """
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

    def get_type(self, indexes="") -> "ABIType":
        indexes = normal_indexes(indexes)
        if len(indexes) == 0:
            return self
        elif self.is_array:
            if indexes[0] == "length":
                return ABIType(typ="uint256")
            else:
                # skip index[0]
                return self.base_type.get_type(indexes[1:])
        elif self.is_tuple:
            arg = get_item_by_index(indexes[0], self.components)
            return arg.get_type(indexes[1:])
        else:
            # string/bytes .length
            assert self.type in ["bytes", "string"], "Should be bytes/string length"
            assert indexes[0] == "length", "Should be length here"
            assert len(indexes) == 1, "length should be end of indexes"
            return ABIType(typ="uint256")

    def extract_value(self, indexes="", values=None):
        """
        Extract the value with the indexes path.
        """
        indexes = normal_indexes(indexes)
        assert eth_abi.is_encodable(self.type_str, values), "Value not match type"

        if len(indexes) == 0:
            # Return the entire value
            return self.normalize(values)

        elif self.is_array:
            assert type(values) in (list, tuple), "Value not array"
            if indexes[0] == "length":
                # Array length
                return len(values)
            else:
                # Get array element
                value = get_item_by_index(indexes[0], values, True)
                return self.base_type.extract_value(indexes[1:], value)

        elif self.is_tuple:
            arg, value = get_item_value_by_index(indexes[0], self.components, values)
            return arg.extract_value(indexes[1:], value)

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

    def _convert_list(self, value):
        if type(value) is str:
            values = ast.literal_eval(value)
        else:
            values = value
        assert isinstance(values, (list, tuple)), f"Invalid list {self}: {value}"
        return values

    def normalize(self, value, is_list=False):
        def _assert(condition, msg):
            if not condition:
                raise ValueError(
                    f"Error while casting `{value}` to `{self.type_str}`: {msg}"
                )

        if is_list:
            values = self._convert_list(value)
            return [self.normalize(i) for i in values]

        if self.is_array:
            value = self.base_type.normalize(value, True)
            if self.array_size != DYNAMIC_SIZE:
                _assert(
                    len(value) == self.array_size, "Value not match fixed-array size"
                )
            return list(value)
        elif self.is_tuple:
            values = self._convert_list(value)
            _assert(len(values) == len(self.components), "Value not match tuple size")

            r = []
            for i, arg in enumerate(self.components):
                v = arg.normalize(values[i])
                r.append(v)
            return tuple(r)
        else:
            if self.type == "string":
                _assert(isinstance(value, str), "string expected")
                return value
            elif self.type.startswith("bytes"):
                _assert(isinstance(value, (str, bytes)), "hexstring/bytes expected")
                _value = HexBytes(value)
                if len(self.type) > 5:
                    expected_size = int(self.type[5:])
                    bytes_size = len(_value)

                    if bytes_size < expected_size:
                        # Note: for bytes use rjust.
                        # 0x1 -> 0x010000....
                        _value = _value.ljust(expected_size, b"\x00")
                        _value = HexBytes(_value)
                    _assert(
                        len(_value) == expected_size,
                        f"bytes too long, expects {expected_size} but got {bytes_size}",
                    )

                # v1.0.0 does not add prefix.
                hexed = _value.hex()
                if not hexed.startswith("0x"):
                    hexed = "0x" + hexed
                return hexed.lower()  # lower case.

            elif self.type.startswith("uint") or self.type.startswith("int"):
                _assert(isinstance(value, int), "int expected")
                bits = int(self.type.strip("uint"))  # remove u, i, n, t chars.
                assert bits % 8 == 0
                size = bits // 8
                signed = self.type.startswith("int")
                try:
                    int.to_bytes(value, size, "big", signed=signed)
                except OverflowError:
                    _assert(False, "Integer value overflow")
                return value
            elif self.type == "bool":
                _assert(isinstance(value, bool), "bool value expected")
                return value
            else:
                _assert(self.type == "address", f"Invalid type str `{self.type}`")
                _assert(
                    type(value) is str and re.match("0x[0-9a-fA-F]{40}", value),
                    "Invalid address",
                )
                return value.lower()  # lower case.

    @classmethod
    def cast(cls, type, value):
        return cls(typ=type).normalize(value)

    @classmethod
    def match_types(cls, value, types=[]) -> bool:
        msgs = []
        for type in types:
            try:
                cls.cast(type, value)
                return True, ""
            except Exception as e:
                msgs.append(str(e))

        return False, ",".join(msgs)
