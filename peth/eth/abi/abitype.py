import ast
import re
from typing import List, Tuple

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


class ABIType:
    def __init__(self, name="", typ=None, components=None, raw=None) -> None:
        if raw is None and typ is None:
            raise ValueError("Either raw or typ must be provided.")
        if raw is not None and not isinstance(raw, dict):
            raise TypeError(f"Invalid raw: expected dict, got {type(raw)}")
        if typ is not None and not isinstance(typ, str):
            raise TypeError(f"Invalid typ: expected str, got {type(typ)}")

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
            if len(self.components) == 0:
                raise ValueError("Tuple type must have at least one component.")
        else:
            self.is_tuple = False
            if len(self.components) != 0:
                raise ValueError("Non-tuple type should not have components.")

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
            s += self.type[len("tuple") :]
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
            if self.is_dynamic_array:
                raise ValueError("Dynamic array has no static size.")
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
        if self.is_tuple:
            s = "("
            s += ",".join(str(i) for i in self.components)
            s += ")"
            s += self.type[len("tuple") :]
            return f"{s} {self.name}"
        else:
            return f"{self.type_str} {self.name}"

    def tuple_get_static_offset(self, name):
        if not self.is_tuple:
            raise TypeError("tuple_get_static_offset called on non-tuple type.")

        static_offset = 0
        for arg in self.components:
            if arg.name == name:
                return static_offset
            static_offset += arg.static_size
        raise NameError(f"{name} not in tuple of {self}")

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
            if self.type not in ["bytes", "string"]:
                raise TypeError("Should be bytes/string length")
            if indexes[0] != "length":
                raise ValueError("Should be length here")
            if len(indexes) != 1:
                raise ValueError("length should be end of indexes")
            return ABIType(typ="uint256")

    def extract_value(self, indexes="", values=None):
        """
        Extract the value with the indexes path.
        """
        indexes = normal_indexes(indexes)
        if not eth_abi.is_encodable(self.type_str, values):
            raise ValueError(f"Value does not match type {self.type_str}")

        if len(indexes) == 0:
            # Return the entire value
            return self.normalize(values)

        elif self.is_array:
            if not isinstance(values, (list, tuple)):
                raise TypeError("Value not array")
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
            if self.type not in ["bytes", "string"]:
                raise TypeError("Should be bytes/string length")
            if indexes[0] != "length":
                raise ValueError("Should be length here")
            if len(indexes) != 1:
                raise ValueError("length should be end of indexes")
            if not isinstance(values, (bytes, str)):
                raise TypeError("Expected bytes or str value")
            return len(values)

    def map_values(self, values, include_type=False) -> Tuple:
        """
        uint256 a
        1
        =>
        ("a", 1)

        include_type=True
        ("a", "uint256", 1)
        """
        if self.is_array:
            if not isinstance(values, (list, tuple)):
                raise TypeError("Value not array")
            r = []
            for i, v in enumerate(values):
                name = f"[{i}]"
                if include_type:
                    _, _, v = self.base_type.map_values(values[i], True)
                    r.append((name, self.base_type.type, v))
                else:
                    _, v = self.base_type.map_values(values[i], False)
                    r.append((name, v))

            if include_type:
                return (self.name, self.type, r)
            else:
                return (self.name, r)

        elif self.is_tuple:
            if not isinstance(values, (list, tuple)):
                raise TypeError("Value not tuple")
            if len(values) != len(self.components):
                raise ValueError("Value not match tuple size")

            r = []
            for i, arg in enumerate(self.components):
                name = f"{arg.name}"
                if include_type:
                    _, _, v = arg.map_values(values[i], True)
                    r.append((name, arg.type, v))
                else:
                    _, v = arg.map_values(values[i], False)
                    r.append((name, v))

            if include_type:
                return (self.name, self.type, r)
            else:
                return (self.name, r)
        else:
            if include_type:
                return (self.name, self.type, values)
            else:
                return (self.name, values)

    def _convert_list(self, value):
        if isinstance(value, str):
            values = ast.literal_eval(value)
        else:
            values = value
        if not isinstance(values, (list, tuple)):
            raise TypeError(f"Invalid list {self}: {value}")
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
            return self._normalize_basic(value)

    def _normalize_basic(self, value):
        def _assert(condition, msg):
            if not condition:
                raise ValueError(
                    f"Error while casting `{value}` to `{self.type_str}`: {msg}"
                )

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
            return bytes(_value)

        elif self.type.startswith("uint") or self.type.startswith("int"):
            if isinstance(value, str):
                if value.startswith("0x"):
                    value = int(value, 16)
                else:
                    value = int(value)
            _assert(isinstance(value, int), "int expected")
            bits = int(
                re.sub(r"^u?int", "", self.type)
            )  # remove "uint" or "int" prefix.
            if bits % 8 != 0:
                raise ValueError(f"Invalid int bit size: {bits}")
            size = bits // 8
            signed = self.type.startswith("int")
            try:
                int.to_bytes(value, size, "big", signed=signed)
            except OverflowError:
                _assert(False, "Integer value overflow")
            return value

        elif self.type == "bool":
            if isinstance(value, str):
                if value.lower() == "true":
                    value = True
                elif value.lower() == "false":
                    value = False

            _assert(isinstance(value, bool), "bool value expected")
            return value

        else:
            _assert(self.type == "address", f"Invalid type str `{self.type}`")
            _assert(
                isinstance(value, str) and re.match("0x[0-9a-fA-F]{40}", value),
                "Invalid address",
            )
            return value.lower()  # lower case.

    @classmethod
    def cast(cls, typ_str, value):
        return cls(typ=typ_str).normalize(value)

    @classmethod
    def match_types(cls, value, types=None) -> tuple:
        if types is None:
            types = []
        msgs = []
        for typ_str in types:
            try:
                cls.cast(typ_str, value)
                return True, ""
            except Exception as e:
                msgs.append(str(e))

        return False, ",".join(msgs)
