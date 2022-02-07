
from web3 import Web3
import eth_abi

from scan import ScanAPI
from sigs import Signature, Signatures

class Peth(object):

    def __init__(self, rpc_url, scan_url) -> None:
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        assert self.web3.isConnected(), "Fail to connect HTTPProvider %s." % rpc_url
        if scan_url:
            self.scan = ScanAPI(scan_url)
        else:
            self.scan = None

    def rpc_call_raw(self, method, args=[]):
        return self.web3.provider.make_request(method, args)

    def rpc_call(self, method, args=[]):
        r = self.rpc_call_raw(method, args)
        if "result" in r:
            return r["result"]
        if "error" in r:
            return "Code: %s, Message: %s" %(r["error"]["code"], r["error"]["message"])
        return r

    def format_address_args(self, args):
        r = []
        for i in args:
            if i.startswith('0x') and len(i) == 42:
                r.append(Web3.toChecksumAddress(i))
            else:
                r.append(i)
        return r


    def eth_call(self, sender, to, sig_or_name, args=[], **kwargs):
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

        args = self.format_address_args(args)
        data = sig.selector
        if sig.args_sig and sig.args_sig != "()":
            data += eth_abi.encode_single(sig.args_sig, args)
        
        tx = {
            "from": sender,
            "to": to,
            "data": "0x" + data.hex()
        }
        tx.update(kwargs)
        r = self.rpc_call_raw('eth_call', [tx, 'latest'])
        if "error" in r:
            return "Code: %s, Message: %s" %(r["error"]["code"], r["error"]["message"])
        
        if "result" in r:
            try:
                data = r["result"][2:] # skip 0x
                data = bytes.fromhex(data)
                if sig.return_sig and sig.return_sig != "()":
                    ret_values = eth_abi.decode_single(sig.return_sig, data)
                    if len(ret_values) == 0:
                        return ret_values[0]
                    else:
                        return ','.join(str(i) for i in ret_values)
                else:
                    return r["result"]
            except Exception as e:
                print("Error in parse return data", e)
                return r
        return r