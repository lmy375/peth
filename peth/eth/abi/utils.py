import re

import eth_abi

abi_encode = getattr(eth_abi, "encode", getattr(eth_abi, "encode_abi", None))
abi_decode = getattr(eth_abi, "decode", getattr(eth_abi, "decode_abi", None))


def normal_indexes(indexes):
    if type(indexes) is str:
        indexes = indexes.replace("[", ".").replace("]", "")
        indexes = indexes.split(".")
        indexes = list(filter(None, indexes))  # Remove ""
    assert type(indexes) is list, "Invalid indexes"
    return indexes


def split_sig(sig: str) -> list:
    sig = re.sub(r"\s", "", sig)  # remove blank chars.
    assert sig.startswith("(") and sig.endswith(")"), f"Invalid sig: {sig}"
    sig = sig[1:-1]  # Remove ()

    types = []
    left = 0

    type_str = ""
    for c in sig:
        if c == "," and left == 0:
            types.append(type_str)
            type_str = ""
            continue

        elif c == "(":
            left += 1

        elif c == ")":
            left -= 1
            assert left >= 0, "Invalid sig: %s" % sig

        type_str += c

    if type_str:
        types.append(type_str)  # Append the last one.

    return types


def convert_typ_to_abi_item(type_str):
    if not type_str.startswith("("):
        return {"name": "", "type": type_str, "internalType": type_str}

    typ = "tuple"
    if type_str.endswith("]"):
        i = type_str.rindex(")") + 1
        typ += type_str[i:]
        type_str = type_str[:i]

    a = {"name": "", "components": [], "type": typ, "internalType": typ}

    i = 0
    for elem_type in split_sig(type_str):
        item = convert_typ_to_abi_item(elem_type)
        item["name"] = "elem%s" % i
        a["components"].append(item)
        i += 1
    return a


def parse_simple_to_json(sig):
    """
    "balanceOf(address)->(uin256) view"
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

    for state_typ in [
        "nonpayable",  # This must be checked before payable
        "payable",
        "view",
        "pure",
    ]:
        if sig.endswith(state_typ):  # Add stateMutability
            sig = sig[: -len(state_typ)]
            a["stateMutability"] = state_typ

    sigs = sig.split("->")
    func_sig = sigs[0]

    idx = func_sig.index("(")
    a["name"] = func_sig[:idx]  # Function name.

    i = 0
    args_sig = func_sig[idx:]
    for arg_type in split_sig(args_sig):
        item = convert_typ_to_abi_item(arg_type)
        item["name"] = "arg%s" % i
        a["inputs"].append(item)
        i += 1

    if len(sigs) == 2:
        return_sig = sigs[1]
        for ret_type in split_sig(return_sig):
            item = convert_typ_to_abi_item(ret_type)
            a["outputs"].append(item)
    return a


def get_item_by_index(index: str, items: list, only_int=False):
    assert type(items) in (tuple, list)
    try:
        # For int index
        i = int(index)
        if i < 0:
            i = len(items) + i
        assert i < len(items), f"tuple index out-of-bound {i} >= {len(items)}"
        return items[i]
    except ValueError:
        if not only_int:
            # For non-int index
            for item in items:
                if item.name == index:
                    return item
        raise KeyError(f"index {index} not valid for list {items}")


def get_item_value_by_index(index: str, items: list, values: list):
    assert type(items) in (tuple, list)
    assert type(values) in (tuple, list)
    assert len(items) == len(values), "length mismatch"

    try:
        # For int index
        i = int(index)
        if i < 0:
            i = len(items) + i
        assert i < len(items), "tuple index out-of-bound"

        return items[i], values[i]
    except ValueError:
        # For non-int index
        for i, item in enumerate(items):
            if item.name == index:
                return item, values[i]

        raise KeyError(f"index {index} not valid for list {items}")
