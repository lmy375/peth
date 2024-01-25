from typing import Dict
import os
import json
import yaml

from hexbytes import HexBytes

from web3 import Web3

from peth.eth.abi import ABI, ExtProcessor, ABIFunction, eth_abi
from peth import Peth

EXPLANATIONS_PATH = os.path.join(os.path.dirname(__file__), "explanations.yaml")
SUBCALLS_PATH = os.path.join(os.path.dirname(__file__), "subcalls.yaml")
ABI_PATH = os.path.join(os.path.dirname(__file__), "abis")

class TxExplainer(ExtProcessor):

    def __init__(self, chain):
        self.peth = Peth.get_or_create(chain)
        self.pattern_abi = ABI([])
        self.explanations: Dict[bytes, str] = {}
        self.subcalls: Dict[bytes, dict] = {}

        self._init_pattern_abi()

        self._init_patterns(EXPLANATIONS_PATH, self.explanations)
        self._init_patterns(SUBCALLS_PATH, self.subcalls)

        self.key_alias = {}

    def _init_patterns(self, path, patterns):
        for k, v in yaml.safe_load(open(path)).items():
            if '(' in k:
                if k in self.pattern_abi.signatures:
                    func = self.pattern_abi.signatures[k]
                else:
                    # This is a sig.
                    func = ABIFunction(k)
                    self.pattern_abi.add_func(func)
            elif k.startswith("0x"):
                func = self.pattern_abi.selectors[HexBytes(k)]
            else:
                if k in self.pattern_abi.functions: 
                    func = self.pattern_abi.functions[k]
                else:
                    if k in self.pattern_abi._name_collisions:
                        raise KeyError(f"{k} matches mutliple functions")
                    else:
                        raise KeyError(f"{k} not found in abi.")
            
            patterns[func.selector] = v

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
        value = self._post_process_with_hint(hint, value, func, values)
        return value
    
    def _process_key(self, key, func, values):
        if key in self.key_alias:
            value = self.key_alias[key]
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

    def _post_process_with_hint(self, hint, value, func, values):
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
            elif typ == "names":
                name_list = json.loads(hint[1])
                for v, name in name_list:
                    if v == value:
                        return name
                return value
        
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
        
    def decode_call(self, to, data, include_sub=True) -> list:
        r = []
        try:
            func = self.pattern_abi._get_function_by_calldata(data)
        except:
            func = self.peth.get_function(to, None, data)

        if func:
            values = func.decode_input(data)
            value_map = func.map_values(values)

            tag = f"{func.full}"
            if to:
                tag = self._process_addr(to) + ' ' + tag

            r.append((tag, value_map))

            subcalls = self.get_subcalls(to, data, 0)
            if subcalls:
                sub_value_maps = []
                for tag, to, data, _ in subcalls:
                    rets = self.decode_call(to, data, include_sub)
                    sub_value_maps.append((
                        f"{tag}",
                        rets
                    ))
                r.append(("Sub calls", sub_value_maps))
        return r

    def decode_tx(self, txid):
        tx = self.peth.web3.eth.get_transaction(txid)
        to = tx["to"]
        data = tx["input"]
        return self.decode_call(to, data)
    
    def get_explanation(self, data) -> str:
        selector = HexBytes(data)[:4]
        return self.explanations.get(selector)

    def explain_call(self, to, data, value=0, include_sub=True, prefix="") -> str:
        s = ''
        expl = self.get_explanation(data)
        if expl is None:
            s += "No explanation."
        else:
            # Prepare alias.
            self.key_alias["tx.to"] = to
            self.key_alias["tx.value"] = value
            s += self.pattern_abi.explain_calldata(expl, data, self)

        if not include_sub:
            return expl

        subcalls = self.get_subcalls(to, data, value)
        for tag, to, data, value in subcalls:
            tag = prefix + tag
            s += f"\n\n**{tag}**: "
            s += self.explain_call(to, data, value, True, tag + ".")
        return s

    def explain_tx(self, txid, include_sub=True):
        tx = self.peth.web3.eth.get_transaction(txid)
        to = tx["to"]
        data = tx["input"]
        value = tx["value"]
        return self.explain_call(to, data, value, include_sub)
    
    def _parse_multisend(self, txbytes) -> list:
        txbytes = HexBytes(txbytes)

        r = []
        i = 0
        while len(txbytes) > 0:
            op = txbytes[0]
            tag = f"multiSend[{i}]." + ("call" if op == 0 else "delegatecall")
            i += 1
            
            txbytes = txbytes[1:]
            to = txbytes[:20].hex()
            assert to.startswith('0x')
            
            txbytes = txbytes[20:]
            value = eth_abi.decode(["uint32"], txbytes[:32])[0]

            txbytes = txbytes[32:]
            datalength = eth_abi.decode(["uint32"], txbytes[:32])[0]

            txbytes = txbytes[32:]
            data = txbytes[: datalength]

            txbytes = txbytes[datalength:]
            r.append((tag, to, data, value))
        return r

    def _customized_get_subcall(self, tx_to=None, tx_data=None, tx_value=0) -> list:
        selector = HexBytes(tx_data)[:4]
        if selector == HexBytes("0x8d80ff0a"): # multiSend(bytes)
            txbytes = eth_abi.decode(["bytes"], HexBytes(tx_data)[4:])[0]
          
            return self._parse_multisend(txbytes)

    def get_subcalls(self, tx_to=None, tx_data=None, tx_value=0):
        assert tx_data is not None

        r = self._customized_get_subcall(tx_to, tx_data, tx_value)
        if r:
            return r

        selector = HexBytes(tx_data)[:4]
        if selector not in self.subcalls:
            return []
        calls = [] # tag, to, data, value
        pattern = self.subcalls[selector]
        if "count" in pattern:
            cnt_index = pattern["count"]
            subcall_cnt = self.pattern_abi.extract_value_from_calldata(cnt_index, tx_data)
            for i in range(subcall_cnt):
                if "to" in pattern:
                    to_idx = pattern["to"].replace("#", str(i))
                    to = self.pattern_abi.extract_value_from_calldata(to_idx, tx_data)
                else:
                    to = tx_to
                
                assert "data" in pattern, 'Invalid subcall pattern: "data" not found'
                data_idx = pattern["data"].replace("#", str(i))
                data = self.pattern_abi.extract_value_from_calldata(data_idx, tx_data)

                if "value" in pattern:
                    value_idx = pattern["value"].replace("#", str(i))
                    value = self.pattern_abi.extract_value_from_calldata(value_idx, tx_data)
                else:
                    value = tx_value
                calls.append((data_idx, to, data, value))
        else:
            if "to" in pattern:
                to = self.pattern_abi.extract_value_from_calldata(pattern["to"], tx_data)
            else:
                to = tx_to
            
            assert "data" in pattern, 'Invalid subcall pattern: "data" not found'
            data = self.pattern_abi.extract_value_from_calldata(pattern["data"], tx_data)
            if "value" in pattern:
                value = self.pattern_abi.extract_value_from_calldata(pattern["value"], tx_data)
            else:
                value = tx_value
            calls.append((pattern["data"], to, data, value))
        return calls

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
