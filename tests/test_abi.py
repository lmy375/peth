from hexbytes import HexBytes
from os import path
import json

from peth.eth.abi import ABI, ABIFunction, ABIType
from peth.core.peth import Peth


BAL_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"

# https://etherscan.io/tx/0xe012b2e0b4f79cbc4e20c634557b6e1826ec3ae3a49cb909d56dd87f0aa0d715
BATCH_SWAP_DATA = HexBytes(
    "0x945bcec900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000030000000000000000000000000037e76af74c7c4994865b04f06b026785e25441b3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037e76af74c7c4994865b04f06b026785e25441b30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000658c016c0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001008bd4a1e74a27182d23b98c10fd21d4fbb0ed4ba00002000000000000000004ed000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000c328093e61ee40000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000b09dea16768f0799065c475be02919503cb2a3500020000000000000000001a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000470ebf5f030ed85fc1ed4c2d36b9dd02e77cf1b70000000000000000000000006b175474e89094c44da98b954eedeac495271d0f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000c328093e61ee4000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffe7f756a9352e86ce"
)

ABI_PATH = path.join(path.dirname(__file__), "bal.json")
if not path.exists(ABI_PATH):
    abi = Peth.get_or_create('eth').scan.get_abi(BAL_VAULT)
    json.dump(abi, open(ABI_PATH, "w"))

BAL_ABI = ABI(json.load(open(ABI_PATH)))

def test_ABIType():
    a = ABIType(typ="uint256[2][3]")

    assert a.type_str == "uint256[2][3]"

    value = [[1, 2], [3, 4], [5, 6]]
    assert a.extract_value("", value) == value
    assert a.extract_value("length", value) == len(value)
    assert a.extract_value("2", value) == value[2]
    assert a.extract_value("[2]", value) == value[2]
    assert a.extract_value("[2][0]", value) == value[2][0]
    assert a.extract_value("[2].length", value) == len(value[2])
    assert a.extract_value("2.length", value) == len(value[2])

    a = ABIType(typ="uint256[][]")
    value = [[1, 2], [3, 4], [5, 6]]
    assert a.extract_value("", value) == value
    assert a.extract_value("length", value) == len(value)
    assert a.extract_value("2", value) == value[2]
    assert a.extract_value("[2]", value) == value[2]
    assert a.extract_value("[2][0]", value) == value[2][0]
    assert a.extract_value("[2].length", value) == len(value[2])
    assert a.extract_value("2.length", value) == len(value[2])


def test_validation():
    def _check_value(typ, value, valid, is_list=False):
        try:
            ABIType(typ=typ).normalize(value, is_list)
            assert valid is True
        except Exception as e:
            print(typ, value, e)
            assert valid is False

    _check_value("uint8", "1", True)
    _check_value("uint8", 1, True)
    _check_value("uint8", "0xff", True)
    _check_value("uint8", "0xfff", False)
    _check_value("uint8", "abcd", False)
    _check_value("uint8", "-1", False)
    _check_value("uint8", -1, False)

    _check_value("int8", -1, True)
    _check_value("int8", "-1", True)
    _check_value("int8", "-0xf", True)
    _check_value("int8", "-0xf0", False)

    _check_value("string", "1", True)
    _check_value("string", "this is string", True)
    _check_value("bytes", "0x", True)
    _check_value("bytes", "0xAA", True)
    _check_value("bytes", "Invalid", False)
    _check_value("bytes32", "0xAAAA", True)
    _check_value("bytes1", "0xAAAA", False)

    _check_value("bool", "True", True)
    _check_value("bool", "1", True)
    _check_value("bool", True, True)
    _check_value("bool", 0x0, True)
    _check_value("bool", "NotBool", False)

    _check_value("address", "0x", False)
    _check_value("address", "0x88c6C46EBf353A52Bdbab708c23D0c81dAA8134A", True)

    _check_value("bool[]", [1, True, "False"], True)
    _check_value("bool", '[1, true, "False"]', True, True)
    _check_value("bool[]", '[1, true, "False"]', True)

    _check_value("(bool[],uint8)", '[[1, true, "False"], 1]', True)


def test_bal_extract_value():
    abi = BAL_ABI
    data = BATCH_SWAP_DATA
    assert abi.get_type("batchSwap.kind").type_str == "uint8"
    assert (
        abi.get_type("batchSwap.swaps").type_str
        == "(bytes32,uint256,uint256,uint256,bytes)[]"
    )
    assert (
        abi.get_type("batchSwap.swaps[0]").type_str
        == "(bytes32,uint256,uint256,uint256,bytes)"
    )
    assert abi.get_type("batchSwap.swaps.length").type_str == "uint256"
    assert abi.get_type("batchSwap.swaps[0].poolId").type_str == "bytes32"

    assert abi.extract_value_from_calldata("batchSwap.kind", data) == 0
    assert abi.extract_value_from_calldata("kind", data) == 0
    assert abi.extract_value_from_calldata("swaps[0].assetInIndex", data) == 0
    assert abi.extract_value_from_calldata("swaps[1].assetInIndex", data) == 1
    assert (
        abi.extract_value_from_calldata("funds.recipient", data)
        == "0x37e76aF74C7C4994865B04F06B026785e25441b3".lower()
    )
    assert abi.extract_value_from_calldata("limits[-1]", data) == -1731820246958962994

    ABI.print_value_map(abi.map_values(data))

    desc = abi.explain_calldata(
        "Sell {{assets[0]}} of {{funds.sender}}, buy {{assets[-1]}} for {{funds.recipient}}, start amount {{swaps[0].amount}}",
        data,
    )
    assert (
        desc
        == "Sell 0x470ebf5f030ed85fc1ed4c2d36b9dd02e77cf1b7 of 0x37e76af74c7c4994865b04f06b026785e25441b3, buy 0x0000000000000000000000000000000000000000 for 0x37e76af74c7c4994865b04f06b026785e25441b3, start amount 3600000000000000000000"
    )


"""
 kind : 0
 swaps :
  [0] :
   poolId : 8bd4a1e74a27182d23b98c10fd21d4fbb0ed4ba00002000000000000000004ed
   assetInIndex : 0
   assetOutIndex : 1
   amount : 3600000000000000000000
   userData : 0x
  [1] :
   poolId : 0b09dea16768f0799065c475be02919503cb2a3500020000000000000000001a
   assetInIndex : 1
   assetOutIndex : 2
   amount : 0
   userData : 0x
 assets :
  [0] : 0x470ebf5f030ed85fc1ed4c2d36b9dd02e77cf1b7
  [1] : 0x6b175474e89094c44da98b954eedeac495271d0f
  [2] : 0x0000000000000000000000000000000000000000
 funds :
  sender : 0x37e76af74c7c4994865b04f06b026785e25441b3
  fromInternalBalance : False
  recipient : 0x37e76af74c7c4994865b04f06b026785e25441b3
  toInternalBalance : False
 limits :
  [0] : 3600000000000000000000
  [1] : 0
  [2] : -1731820246958962994
 deadline : 1703674220
"""


def test_abi():
    abi = BAL_ABI
    assert len(abi.functions) == 26
    assert len(abi._name_collisions) == 0

    assert abi.batchSwap.name == "batchSwap"
    assert abi.batchSwap.selector == HexBytes("0x945bcec9")
    assert (
        abi.batchSwap.signature
        == "batchSwap(uint8,(bytes32,uint256,uint256,uint256,bytes)[],address[],(address,bool,address,bool),int256[],uint256)"
    )
    assert (
        abi.batchSwap.input_type_str
        == "(uint8,(bytes32,uint256,uint256,uint256,bytes)[],address[],(address,bool,address,bool),int256[],uint256)"
    )
    assert (
        abi.batchSwap.simple
        == "batchSwap(uint8,(bytes32,uint256,uint256,uint256,bytes)[],address[],(address,bool,address,bool),int256[],uint256)->(int256[])"
    )
    assert (
        abi.batchSwap.full
        == "function batchSwap(uint8 kind, (bytes32,uint256,uint256,uint256,bytes)[] swaps, address[] assets, (address,bool,address,bool) funds, int256[] limits, uint256 deadline) returns (int256[] assetDeltas)"
    )

    ret = ((1, -1),)
    data = abi.batchSwap.encode_output(ret)
    assert abi.batchSwap.decode_output(data) == ret

    args = abi.batchSwap.decode_input(BATCH_SWAP_DATA)
    data = abi.batchSwap.encode_input(args)

    assert abi.batchSwap.decode_input(data) == args
    assert abi.batchSwap.encode_input(args) == data


def test_simple_sig():
    abi = BAL_ABI
    data = BATCH_SWAP_DATA

    sig = abi.batchSwap.simple
    func = ABIFunction(sig)
    assert func.simple == sig

    abi2 = ABI([sig])
    assert abi2.batchSwap.simple == sig

    ABI.print_value_map(abi2.map_values(data))
    assert (
        abi2.extract_value_from_calldata("arg3.elem2", data)
        == "0x37e76af74c7c4994865b04f06b026785e25441b3"
    )
    assert (
        abi2.extract_value_from_calldata("3.2", data)
        == "0x37e76af74c7c4994865b04f06b026785e25441b3"
    )
    assert abi2.extract_value_from_calldata("1.0.2", data) == 1
    assert abi2.extract_value_from_calldata("1[0].2", data) == 1

