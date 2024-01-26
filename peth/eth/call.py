from web3 import Web3
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from eth_account import Account
from hexbytes import HexBytes

from .scan import ScanAPI
from .sigs import Signature, Signatures
from .abi import ABIFunction, ABI
from . import utils
from peth.core.log import logger
from peth.util.solc import compile_with_eth_call

class EthCall(object):
    """
    The base class of Peth which implements basic eth_call related functions.
    """

    def __init__(self, rpc_url, api_url, address_url, chain="Custom", sender=utils.ZERO_ADDRESS, private_key=None) -> None:
        self.chain = chain
        self.rpc_url = rpc_url
        self.api_url = api_url
        self.address_url = address_url
        self.sender = sender
        if private_key:
            self.signer = Account.from_key(private_key)
        else:
            self.signer = None

        if rpc_url.startswith('http'):
            self.provider = Web3.HTTPProvider(rpc_url)
        elif rpc_url.startswith('ws'):
            self.provider = Web3.WebsocketProvider(rpc_url)
        elif rpc_url.endswith('ipc'):
            self.provider = Web3.IPCProvider(rpc_url)
        else:
            raise NotImplementedError("Unknown url type. HTTP/IPC/WS required. %s" % rpc_url)

        self.web3 = Web3(self.provider)

        try:
            self.web3.eth.get_block("latest")
        except Exception as e:
            if "POA chain" in str(e):
                from web3.middleware import geth_poa_middleware
                self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
            else:
                raise e
            
        if api_url:
            self.scan: ScanAPI = ScanAPI.get_or_create(api_url)
        else:
            self.scan = None

    def get_address_url(self, addr):
        if self.address_url:
            return self.address_url + addr

    def rpc_call_raw(self, method, args=[]):
        logger.debug("PRC request: method=%s args=%s" %(method, args))
        r = self.web3.provider.make_request(method, args)
        logger.debug("PRC result: %s " % r)
        return r

    def rpc_call(self, method, args=[]):
        r = self.rpc_call_raw(method, args)
        if "result" in r:
            return r["result"]
        if "error" in r:
            return "Code: %s, Message: %s" %(r["error"]["code"], r["error"]["message"])
        return r
    
    def get_function(self, to=None, sig=None, data=None) -> ABIFunction:
        """
        to: contract address.
        sig: function signature or function name.
        data: calldata.

        Options:
            to + sig: contract address + function name/sig => Full ABI
            to + data: contract address + selector => Full ABI
            sig: simple signature => Simple ABI
            data: selector => Simple ABI
        """
        func = None
        data = HexBytes(data) if data else HexBytes("0x")
        selector = data[:4] if len(data) >= 4 else None

        if to:
            abi_json = self.scan.get_abi(to)
            if abi_json:
                abi = ABI(abi_json)

                if sig in abi.signatures:
                    func = abi.signatures[sig]
                elif sig in abi.functions:
                    func = abi.functions[sig]

                if selector:
                    if func:
                        assert func.selector == selector, "Function not match calldata"
                    else:
                        if selector in abi.selectors:
                            func = abi.selectors[selector]         
        
                if func:
                    return func
        
   
        if sig:
            func = ABIFunction(sig)
            if func:
                if selector:
                    assert func.selector == selector, "Function not match calldata"
                return func

        if selector:
            sig = utils.selector_to_sigs(selector, True)
            if sig:
                return ABIFunction(sig)
        
        # No signature found.
        return None

    def eth_call(self, to, sig_or_name, args=[], sender=None, throw_on_revert=False, **kwargs):
        """
        Construct tx data and perform eth_call RPC call.

        NOTE:
        1. utils.process_args is used to convert int/address-like string arguments to int/address. 
           (Maybe we should move this to an upper layer.)
        2. When throw_on_revert=True, we raise exceptions when tx reverts or return data is not properly decodes.
        """
        args = utils.process_args(args)
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

        data = sig.encode_args(args)

        if not sender:
            sender = self.sender
        
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
            return r

        if "result" in r:
            try:
                ret = sig.decode_ret(r["result"])
                if ret is not None:
                    return ret
                else: 
                    # If no output sig, return raw data.
                    return r["result"]
            except Exception as e:
                if throw_on_revert:
                    raise Exception from e
                return r
        return r

    def call_contract(self, contract, sig_or_name, args=[], sender=None, value=None, silent=True):
        """
        If revert, print error message and return None. 
        So we never throws here and it can be safely used.
        """
        try:
            if value:
                return self.eth_call(contract, sig_or_name, args, sender, True, value=value)
            else:
                return self.eth_call(contract, sig_or_name, args, sender, True)
        except Exception as e:
            if not silent:
                logger.warning('EthCall.call_contract Call %s %s %s' % (contract, sig_or_name, e))
            return None
    
    def run_solidity(self, code):
        """
        Compile and run the Executor.run() code with EthCall contract constructor.
        """

        assert "Executor" in code and "run" in code, "Executor.run() is not defined in such code."

        output = compile_with_eth_call(code)
        calldata = output['<stdin>:EthCall']['bin']
        abi = None
        for abi in output['<stdin>:Executor']['abi']:
            if abi['type'] == 'function' and abi['name'] == 'run':
                break
        
        if abi is None:
            raise Exception("Executor.run() not found in the code")

        s = Signature.from_abi(abi)
        
        tx = {
            "from": self.sender,
            "data": "0x" + calldata
        }

        # print(tx)
        r = self.rpc_call_raw('eth_call', [tx, 'latest'])
        # print(r)
        if "error" in r:
            return r

        if "result" in r:
            try:
                ret = s.decode_ret(r["result"])
                if ret is not None:
                    return ret
                else: 
                    # If no output sig, return raw data.
                    return r["result"]
            except Exception as e:
                return r
        return r

    def send_transaction(self, data=None, to=None, value=None, dry_run=False):
        assert self.signer, "send_transaction: signer not set."

        tx = {
            "from": self.signer.address
        }

        if data:
            tx["data"] = data

        if to:
            tx["to"] =  Web3.toChecksumAddress(to)  
        
        if value:
            tx["value"] = value

        tx["chainId"] = self.web3.eth.chain_id
        tx["nonce"] = self.web3.eth.get_transaction_count(self.signer.address) 

        gas = self.web3.eth.estimate_gas(tx)
        tx["gas"] = int(gas * 1.2)

        gas_price = rpc_gas_price_strategy(self.web3)
        tx["gasPrice"] = int(gas_price * 1.2)
        signed_tx = self.signer.sign_transaction(tx)
        if dry_run:
            return tx, signed_tx
        
        r = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return r
    

    def get_logs(self, address=None, topics=[], start=None, end=None, step=3000, count=50):
        eth = self.web3.eth
        if end is None:
            end = eth.block_number
        if start is None:
            start = 0
        
        for _ in range(count):
            if end <= start:
                return
            
            temp_start = end - step
            filter_params = {
                "fromBlock": temp_start,
                "toBlock": end
            }
            if address:
                filter_params["address"] = Web3.toChecksumAddress(address)
            if topics:
                filter_params["topics"] = topics

            for log in eth.get_logs(filter_params):
                yield log
            end = temp_start - 1
