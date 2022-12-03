import json

from peth.eth.sigs import Signature


def test_human_abi():
    s = Signature.from_sig("balanceOf(address)->(uint256)")
    assert s.selector.hex() == "70a08231"
    assert s.type == Signature.FUNCTION
    assert str(s) == "0x70a08231 function balanceOf(address) returns (uint256)"
    assert s.func_sig == "balanceOf(address)"
    assert s.inputs_sig == "(address)"
    assert s.outputs_sig == "(uint256)"


JSON_ABI_ITEM = """
    {
        "constant": true,
        "inputs": [
            {
                "internalType": "address",
                "name": "owner",
                "type": "address"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    }
"""

def test_json():
    abi = json.loads(JSON_ABI_ITEM)
    s = Signature.from_abi(abi)
    assert s.selector.hex() == "70a08231"
    assert s.type == Signature.FUNCTION
    assert str(s) == "0x70a08231 function balanceOf(address owner) view returns (uint256)"
    assert s.func_sig == "balanceOf(address)"
    assert s.inputs_sig == "(address)"
    assert s.outputs_sig == "(uint256)"



ADDRESS = "0x0eD7e52944161450477ee417DE9Cd3a859b14fD0"
CALL_DATA = '70a082310000000000000000000000000ed7e52944161450477ee417de9cd3a859b14fd0'

def test_enc_dec():
    s = Signature.from_sig("balanceOf(address)->(uint256)")
    assert s.encode_args([ADDRESS]).hex() == CALL_DATA
    assert s.decode_args(CALL_DATA) == (ADDRESS.lower(),)


def test_tuple():
    types = Signature.split_sig("(uint256,(uint256,uint256)[], (string, string))") 
    assert types == ['uint256', '(uint256,uint256)[]', '(string,string)']

    s = Signature.from_sig("func(uint256,(uint256,uint256))->(uint256[])")
    assert s.inputs_sig == '(uint256,(uint256,uint256))'
    assert s.outputs_sig == '(uint256[])'
    assert str(s) == '0xd5cd2bfd function func(uint256, (uint256,uint256)) returns (uint256[])'