from typing import List, Tuple

from web3 import Web3

from peth.core.analysis import AccountAnalysis, Project
from peth.core.config import config
from peth.eth.bytecode import Code
from peth.eth.opcodes import OpCode
from peth.eth.web3ex import Web3Ex


class Peth(Web3Ex):
    """
    The core class which implements real peth command logic.
    This class should be API-friendly and easily scriptable.
    If any feature in console.py is found to be very useful,
    it's better to be moved here for API usage.
    """

    __cache__ = {}

    @classmethod
    def get_or_create(cls, chain) -> "Peth":
        """
        Better entry to create the Peth instance.
        """
        cfg = config.chains
        assert chain in cfg.keys(), f"Invalid chain {chain}. See {config.chains_path}."
        if chain not in cls.__cache__:
            rpc_url = cfg[chain][0]
            api_url = cfg[chain][1]
            address_url = cfg[chain][2]
            cls.__cache__[chain] = cls(rpc_url, api_url, address_url, chain)
        return cls.__cache__[chain]

    def get_view_value(self, contract, name, typ=None):
        """
        Retrive contract view values. such as `name()->(string)`.
        """
        if typ:
            sig = f"{name}()->({typ})"
        else:
            sig = f"{name}()"
        return self.call_contract(contract, sig, [])

    def get_decompile_url(self, addr):

        if "eth" in self.chain:
            url = "https://library.dedaub.com/contracts/Ethereum/" + addr
        elif "matic" in self.chain:
            url = "https://library.dedaub.com/contracts/Polygon/" + addr
        else:
            url = self.address_url.replace("address/", "bytecode-decompiler?a=") + addr

        return url

    def analyze_bytecode(self, addr, code, callback) -> List[Tuple[bytes, str]]:

        if code is None:
            addr = Web3.to_checksum_address(addr)
            bytes_code = bytes(self.web3.eth.get_code(addr))
            code = Code(bytes_code)

        while True:
            ins = code.next_instruction()

            if ins is None:
                break
            callback(ins)

    def get_selectors(self, addr):
        """
        Disassemble the bytecode and return extracted selectors.
        """
        selectors = []

        def _collect(ins):
            # TODO: opt this.
            # DUP1 PUSH4 0x2E64CEC1 EQ PUSH1 0x37 JUMPI --> DEST
            # https://github.com/shazow/whatsabi/blob/main/src.ts/index.ts
            if ins.op is OpCode.PUSH4:
                if ins.opnd == 0xFFFFFFFF or ins.opnd < 0xFFFF:
                    # Skip -1 and small value.
                    return

                selector = ins.opnd.to_bytes(4, "big")
                if selector.isascii():
                    # Skip ASCII string.
                    return

                if selector not in selectors:
                    selectors.append(selector)

        self.analyze_bytecode(addr, None, _collect)
        return selectors

    def get_hardcoded_addresses(self, addr):
        """
        Disassemble the bytecode and return possible hardcoded addresses.
        """
        addresses = []

        def _collect(ins):
            if ins.op is OpCode.PUSH32 or ins.op is OpCode.PUSH20:
                if ins.opnd < 2**160:
                    raw_bytes = ins.opnd.to_bytes(20, "big")
                    addr = "0x" + raw_bytes.hex()
                    addr = Web3.to_checksum_address(addr)
                    if addr not in addresses:
                        if self.web3.eth.get_transaction_count(addr):
                            # Use nonce to filter false positive cases.
                            # Note: Contract's nonce will be 1.
                            addresses.append(addr)

        self.analyze_bytecode(addr, None, _collect)
        return addresses

    def analyze_address(self, addr):
        account = AccountAnalysis(self, addr)
        account.analyze()
        return account

    def analyze_addresses(self, addresses):
        project = Project(self, addresses)
        project.analyze_all()
        return project

    def get_portfolio(self, addresses=[]) -> List[dict]:
        infos = {}  # addr => info
        for token in config.tokens[self.chain]:
            infos[token["address"].lower()] = token
        token_balances = self.get_token_balances(list(infos.keys()), addresses)
        portfolio = {}  # addr => tokens
        for token_addr, user_addr, balance in token_balances:
            if user_addr not in portfolio:
                portfolio[user_addr] = []

            info = infos[token_addr.lower()]
            portfolio[user_addr].append(
                {
                    "token": token_addr,
                    "balance": balance,
                    "info": info,
                    "usd": balance * info["price"] / (10 ** info["decimals"]),
                }
            )
        return portfolio

    def withdraw_balance(self, to, gas_price_rate=1.2, gas_limit_rate=1):
        assert self.signer

        balance = self.web3.eth.get_balance(self.signer.address)
        tx = {"to": to, "value": 1}
        self.populate_tx(tx, self.signer.address, gas_price_rate, gas_limit_rate)
        fee = self.get_tx_gas_fee(tx)
        if balance <= fee:
            raise Exception(f"balance {balance} > fee {fee}")

        tx["value"] = balance - fee
        return self.send_tx(tx)
