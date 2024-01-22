from typing import Dict
import os
import json
import yaml

from hexbytes import HexBytes

from web3 import Web3

from peth.eth.abi import ABI, ExtProcessor, ABIFunction
from peth import Peth

PATTERN_PATH = os.path.join(os.path.dirname(__file__), "patterns.yaml")
ABI_PATH = os.path.join(os.path.dirname(__file__), "abis")

class TxExplainer(ExtProcessor):

    def __init__(self, chain):
        self.peth = Peth.get_or_create(chain)
        self.patterns: Dict[bytes, str] = {}
        self.pattern_abi = ABI([])

        # Init ABI first as patterns relies on this.
        self._init_pattern_abi()
        self._init_patterns()

        self.pattern_alias = {}

    def _init_patterns(self):
        for k, v in yaml.safe_load(open(PATTERN_PATH)).items():
            if '(' in k:
                func = self.pattern_abi.signatures[k]
            elif k.startswith("0x"):
                func = self.pattern_abi.selectors[HexBytes(k)]
            else:
                func = self.pattern_abi.functions[k] 
            
            self.patterns[func.selector] = v

    def _init_pattern_abi(self, abi_dir=ABI_PATH):
        for dir_path, _, files in os.walk(abi_dir):
            for file_name in files:
                if file_name.endswith(".json"):
                    file_path = os.path.join(dir_path, file_name)
                    abi = json.load(open(file_path))
                    abi = ABI(abi)
                    self.pattern_abi.merge(abi)

    # ExtProcessor functions.

    def process(self, func: ABIFunction, key: str, values):
        s = key.split(ExtProcessor.SEP_MARKER)
        key = s[0]
        hint = s[1:]
        value = self._process_key(key, func, values)
        value = self._post_process(hint, value, func, values)
        return value
    
    def _process_key(self, key, func, values):
        if key in self.pattern_alias:
            value = self.pattern_alias[key]
        else:
            value = func.extract_value(key, values)
        return value

    def _process_int(self, value):
        if value < 1e9 * 100:
            return '%s' % value
        elif value < 1e18 * 100:
            return '%f * 1e9' % (value / 1e9)
        else:
            return '%f * 1e18' % (value / 1e18)
    
    def _process_addr(self, addr):
        addr = self.peth.web3.toChecksumAddress(addr)
        name = self.peth.call_contract(addr, "symbol()->(string)")
        if name is None:
            name = self.peth.scan.get_contract_name(addr)
        if name is None:
            codesize = len(self.peth.web3.eth.get_code(addr))

            if codesize:
                name = "Contract(%s..%s)" % (addr[:6], addr[-4:])
            else:
                name = "EOA(%s..%s)" % (addr[:6], addr[-4:])
        return f"[{name}]({self.peth.get_address_url(addr)})"

    def _post_process(self, hint, value, func, values):
        if hint:
            typ = hint[0]
            if typ == 'balance':
                arg = hint[1]
                if arg.lower() == 'eth':
                    decimals = 18
                else:
                    token = self._process_key(arg, func, values)
                    decimals = self.peth.call_contract(token, "decimals()->(uint256)")
                return "%f * 1e%s" % (value/(10**decimals), decimals)
            elif typ == "path":
                tokens = [self._process_addr(i) for i in value]
                return ' -> '.join(tokens)
        return self._fallback_process(value)

    def _fallback_process(self, value):
        if type(value) in (list, tuple):
            return ', '.join(str(self._fallback_process(v)) for v in value)

        if type(value) is int:
            return self._process_int(value)
        
        if Web3.isAddress(value):
            return self._process_addr(value)
        
        return value

    # Decoding.
        
    def decode_call(self, to, data):
        try:
            return self.pattern_abi.map_values(data)
        except:
            pass

        func = self.peth.get_function(to, None, data)
        if func:
            values = func.decode_input(data)
            value_map = func.map_values(values)
            return value_map
        else:
            return None

    def decode_tx(self, txid):
        tx = self.peth.web3.eth.get_transaction(txid)
        to = tx["to"]
        data = tx["input"]
        return self.decode_call(to, data)
    
    def get_pattern(self, data) -> str:
        selector = HexBytes(data)[:4]
        return self.patterns.get(selector)

    def explain_call(self, to, data, value=0) -> str:
        pattern = self.get_pattern(data)
        if pattern is None:
            return None
        
        # Prepare alias.
        self.pattern_alias["tx.to"] = to
        self.pattern_alias["tx.value"] = value
        return self.pattern_abi.explain_calldata(pattern, data, self)

    def explain_tx(self, txid):
        tx = self.peth.web3.eth.get_transaction(txid)
        to = tx["to"]
        data = tx["input"]
        value = tx["value"]
        return self.explain_call(to, data, value)


    def value_map_to_md(self, value_map, indent=0):
        s = ''
        for k, v in value_map:
            if type(v) in (tuple, list):
                s += '  ' * indent + f"- **{k}**:\n"
                s += self.value_map_to_md(v, indent+1) + "\n"
            else:
                if type(v) is bytes:
                    v = v.hex()
                    if len(v) == 0:
                        v = "0x"

                s += '  ' * indent + f"- **{k}**: " + str(self._fallback_process(v)) + '\n'
       
        # Remove last newline.
        s = s.strip('\n')
        return s
