import time

from eth_account import Account
from hexbytes import HexBytes
from web3 import Web3
from web3.gas_strategies.rpc import rpc_gas_price_strategy

from peth.core.log import logger
from peth.util.solc import compile_with_eth_call

from . import utils
from .abi import ABI, ABIFunction
from .contract import Contract
from .scan import ScanAPI


class Web3Ex(object):
    """
    The base class of Peth which implements basic eth_call related functions.
    """

    def __init__(
        self,
        rpc_url,
        api_url,
        address_url,
        chain="Custom",
        sender=utils.ZERO_ADDRESS,
        private_key=None,
    ) -> None:
        self.chain = chain
        self.rpc_url = rpc_url
        self.api_url = api_url
        self.address_url = address_url
        self.sender = sender
        self.signer = None

        if private_key:
            self.bind_signer(private_key)

        if rpc_url.startswith("http"):
            self.provider = Web3.HTTPProvider(rpc_url)
        elif rpc_url.startswith("ws"):
            self.provider = Web3.WebsocketProvider(rpc_url)
        elif rpc_url.endswith("ipc"):
            self.provider = Web3.IPCProvider(rpc_url)
        else:
            raise NotImplementedError(
                "Unknown url type. HTTP/IPC/WS required. %s" % rpc_url
            )

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

    def bind_signer(self, private_key):
        self.signer = Account.from_key(private_key)

    def is_contract(self, addr):
        addr = self.web3.toChecksumAddress(addr)
        return len(self.web3.eth.get_code(addr)) != 0

    def get_address_url(self, addr):
        assert self.address_url, "address_url not set"
        return self.address_url + addr

    def rpc_call(self, method, args=[]):
        logger.debug(f"rpc_call: {method} {args}")
        r = self.web3.provider.make_request(method, args)
        logger.debug(f"rpc_call returns: {r}")
        if "result" in r:
            return r["result"]
        raise Exception(f"rpc_call error: returns {r}")

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

    def eth_call_raw(self, to, data, sender=None, value: int = 0):
        if not sender:
            sender = self.sender

        tx = {
            "from": sender,
            "to": to,
            "data": HexBytes(data).hex(),
            "value": hex(value),
        }
        return self.rpc_call("eth_call", [tx, "latest"])

    def _sig_name_to_func(self, to, sig_or_name):
        if type(sig_or_name) is str:
            if "(" in sig_or_name:
                func = ABIFunction(sig_or_name)
            else:
                # Auto load.
                abi = ABI(self.scan.get_abi(to))
                func = abi.get_func_abi(sig_or_name)
        elif type(sig_or_name) is ABIFunction:
            func = sig_or_name
        else:
            raise ValueError(f"Invalid sig_or_name {sig_or_name}")
        return func

    def eth_call(
        self,
        to,
        sig_or_name,
        args=[],
        sender=None,
        value: int = 0,
        silent: bool = False,
    ):
        """
        Construct tx data and perform eth_call RPC call.
        If silent=False raise exceptions when tx reverts or return data is not properly decodes.
        """
        func = self._sig_name_to_func(to, sig_or_name)

        try:

            input = func.encode_input(args)
            output = self.eth_call_raw(to, input, sender, value)
            ret = func.decode_output(output)
            if ret is not None:
                return ret
        except Exception as e:
            if not silent:
                raise e

    def call_contract(
        self, contract, sig_or_name, args=[], sender=None, value: int = 0, silent=False
    ):
        """
        If tx reverts, print error message and return None.
        So we never throws here and it can be safely used without try-except codes.
        """
        try:
            return self.eth_call(contract, sig_or_name, args, sender, value, silent)
        except Exception as e:
            if not silent:
                logger.warning(
                    "Web3Ex.call_contract Call %s %s %s" % (contract, sig_or_name, e)
                )
            return None

    # Alias
    call = call_contract

    def run_solidity(self, code):
        """
        Compile and run the Executor.run() code with Wrapper contract constructor.
        """

        assert (
            "Executor" in code and "run" in code
        ), "Executor.run() is not defined in such code."

        output = compile_with_eth_call(code)
        calldata = output["<stdin>:Wrapper"]["bin"]
        abi = None
        for abi in output["<stdin>:Executor"]["abi"]:
            if abi["type"] == "function" and abi["name"] == "run":
                break

        if abi is None:
            raise Exception("Executor.run() not found in the code")

        func = ABIFunction(abi)

        tx = {"from": self.sender, "data": "0x" + calldata}

        # print(tx)
        r = self.rpc_call("eth_call", [tx, "latest"])
        # print(r)
        try:
            ret = func.decode_output(r)
            if ret is not None:
                return ret
            else:
                return r
        except Exception:
            return r

    def send_transaction(self, data=None, to=None, value=None, dry_run=False, wait=0):
        assert self.signer, "send_transaction: signer not set."

        tx = {"from": self.signer.address}

        if data:
            tx["data"] = data

        if to:
            tx["to"] = Web3.toChecksumAddress(to)

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

        current_block = self.web3.eth.block_number
        txid = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        if not wait:
            return txid

        wait_sec = 15
        if type(wait) in (float, int) and wait > 0:
            wait_sec = wait

        start_time = time.time()
        while True:
            if time.time() - start_time > wait_sec:
                raise TimeoutError(f"{wait_sec} s timeout. No receipt get.")

            new_block = self.web3.eth.block_number
            if new_block == current_block:
                time.sleep(0.1)
                continue

            return self.web3.eth.get_transaction_receipt(txid)

    def send(
        self, contract, sig_or_name, args=[], value: int = 0, dry_run=False, wait=0
    ):
        func = self._sig_name_to_func(contract, sig_or_name)
        data = func.encode_input(args)
        return self.send_transaction(data, contract, value, dry_run, wait)

    def get_logs(
        self, address=None, topics=[], start=None, end=None, step=100, count=100
    ):
        eth = self.web3.eth
        if end is None:
            end = eth.block_number
        if start is None:
            start = 0

        for _ in range(count):
            if end <= start:
                return

            temp_start = end - step
            filter_params = {"fromBlock": temp_start, "toBlock": end}
            if address:
                filter_params["address"] = Web3.toChecksumAddress(address)
            if topics:
                filter_params["topics"] = topics

            for log in eth.get_logs(filter_params):
                yield log
            end = temp_start - 1

    def contract(self, address, abi: str | ABI | dict = None):
        if abi is None:
            abi = self.scan.get_abi(address)
        elif self.web3.isAddress(str(abi)):
            abi = self.scan.get_abi(str(abi))

        return Contract(self, address, abi)
