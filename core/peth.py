
from web3 import Web3
import eth_abi

from core.config import config
from eth.scan import ScanAPI
from eth.sigs import Signature, Signatures
from eth.utils import process_args

from util.graph import ContractRelationGraph


class Peth(object):

    cache = {}

    def __init__(self, rpc_url, api_url, address_url, chain="Custom") -> None:
        self.chain = chain
        self.rpc_url = rpc_url
        self.api_url = api_url
        self.address_url = address_url

        self.web3 = Web3(Web3.HTTPProvider(rpc_url))

        # assert self.web3.isConnected(), "Fail to connect HTTPProvider %s." % rpc_url
        
        if api_url:
            self.scan = ScanAPI.get_or_create(api_url)
        else:
            self.scan = None
    
    def print_info(self):
        print("Chain:", self.chain)
        print("RPC:", self.rpc_url)
        print("API:", self.api_url)
        print("Address:", self.address_url)

    def get_address_url(self, addr):
        if self.address_url:
            return self.address_url + addr

    def rpc_call_raw(self, method, args=[]):
        return self.web3.provider.make_request(method, args)

    def rpc_call(self, method, args=[]):
        r = self.rpc_call_raw(method, args)
        if "result" in r:
            return r["result"]
        if "error" in r:
            return "Code: %s, Message: %s" %(r["error"]["code"], r["error"]["message"])
        return r

    def eth_call(self, to, sig_or_name, args=[], sender=None, throw_on_revert=False, **kwargs):
        args = process_args(args)
        if type(sig_or_name) is str:
            if '(' in sig_or_name:
                sig = Signature.from_sig(sig_or_name)
            else:
                # Auto load.
                sigs = Signatures(self.scan.get_abi(to))
                sig = sigs.find_by_name(sig_or_name)
        elif type(sig_or_name) is Signature:
            sig = sig_or_name
        else:
            assert False, f"Invalid sig_or_name {sig_or_name}"

        data = sig.selector
        if sig.args_sig and sig.args_sig != "()":
            data += eth_abi.encode_single(sig.args_sig, args)
        
        if not sender:
            sender = '0x0000000000000000000000000000000000000000'
        
        tx = {
            "from": sender,
            "to": to,
            "data": "0x" + data.hex()
        }
        tx.update(kwargs)
        r = self.rpc_call_raw('eth_call', [tx, 'latest'])
        if "error" in r:
            msg = "Code: %s, Message: %s" %(r["error"]["code"], r["error"]["message"])
            if throw_on_revert:
                raise Exception(msg)
            return msg

        if "result" in r:
            try:
                data = r["result"][2:] # skip 0x
                data = bytes.fromhex(data)
                if sig.return_sig and sig.return_sig != "()":
                    ret_values = eth_abi.decode_single(sig.return_sig, data)
                    if len(ret_values) == 1:
                        return ret_values[0]
                    else:
                        return ret_values
                else:
                    return r["result"]
            except Exception as e:
                print("Error in parse return data", e)
                if throw_on_revert:
                    raise Exception from e
                return r
        return r

    def call_contract(self, contract, sig_or_name, args=[], sender=None, value=None):
        """
        If revert, print error message and return None.
        """
        try:
            if value:
                return self.eth_call(contract, sig_or_name, args, sender, True, value=value)
            else:
                return self.eth_call(contract, sig_or_name, args, sender, True)
        except Exception as e:
            print('[*] Call %s %s %s' % (contract, sig_or_name, e))
            return None

    def print_contract_graph(self, addr, include_view=False):
        addr = Web3.toChecksumAddress(addr)
        graph = ContractRelationGraph(addr, self)
        graph.visit(addr, include_view)
        graph.print_assets()
        print("=====================")
        print(graph.dump())
        print("=====================")
        print("Open http://relation-graph.com/#/options-tools and paste the json.")

    @classmethod
    def get_or_create(cls, chain):
        assert chain in config.keys(), f"Invalid chain {chain}. See config.json."
        if chain not in cls.cache:
            rpc_url = config[chain][0]
            api_url = config[chain][1]
            address_url = config[chain][2]
            cls.cache[chain] = cls(rpc_url, api_url, address_url, chain)
        return cls.cache[chain]