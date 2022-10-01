from web3 import Web3

from peth.eth.call import EthCall
from peth.eth.bytecode import Code
from peth.eth.opcodes import OpCode

from peth.core.config import chain_config
from peth.core.analysis import AccountAnalysis, Project


class Peth(EthCall):
    """
    The core class which implements real peth command logic.
    This class should be API-friendly and easily scriptable.
    Do NOT perform arguments validation or output prints here, console.py is a better choice.
    """

    __cache__ = {}

    @classmethod
    def get_or_create(cls, chain) -> 'Peth':
        """
        Better entry to create the Peth instance.
        """
        assert chain in chain_config.keys(), f"Invalid chain {chain}. See config.json."
        if chain not in cls.__cache__:
            rpc_url = chain_config[chain][0]
            api_url = chain_config[chain][1]
            address_url = chain_config[chain][2]
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
            url = self.address_url.replace(
                "address/", "bytecode-decompiler?a=") + addr

        return url
    
    def analyze_bytecode(self, addr=None, code=None):
        
        if code is None:
            addr = Web3.toChecksumAddress(addr)
            bytes_code = bytes(self.web3.eth.get_code(addr))
            code = Code(bytes_code)

        selectors = []
        addresses = []

        while True:
            ins = code.next_instruction()

            if ins is None:
                break

            # TODO: opt this. 
            # DUP1 PUSH4 0x2E64CEC1 EQ PUSH1 0x37 JUMPI --> DEST
            # https://github.com/shazow/whatsabi/blob/main/src.ts/index.ts
            if ins.op is OpCode.PUSH4:
                if ins.opnd == 0xffffffff or ins.opnd < 0xffff:
                    # Skip -1 and small value.
                    continue

                selector = ins.opnd.to_bytes(4, 'big')
                if selector.isascii():
                    # Skip ASCII string.
                    continue

                if selector not in selectors:
                    selectors.append(selector)
            
            if ins.op is OpCode.PUSH32 or ins.op is OpCode.PUSH20:
                if ins.opnd < 2**160:
                    raw_bytes = ins.opnd.to_bytes(20, 'big')
                    addr = '0x' + raw_bytes.hex()
                    addr = Web3.toChecksumAddress(addr)
                    if addr not in addresses:
                        if self.web3.eth.get_transaction_count(addr):
                            # Use nonce to filter false positive cases.
                            # Note: Contract's nonce will be 1.
                            addresses.append(addr)
        
        return selectors, addresses

    def get_selectors(self, addr):
        """
        Disassemble the bytecode and return extracted selectors.
        """
        selectors, _ = self.analyze_bytecode(addr)
        return selectors

    def get_hardcoded_address(self, addr):
        """
        Disassemble the bytecode and return possible hardcoded addresses.
        """
        _, addresses = self.analyze_bytecode(addr)
        return addresses


    def is_contract(self, addr):
        addr = self.web3.toChecksumAddress(addr)
        return len(self.web3.eth.get_code(addr)) != 0


    def analyze_address(self, addr):
        account = AccountAnalysis(self, addr)
        account.analyze()
        return account

    def analyze_addresses(self, addresses):
        project = Project(self, addresses)
        project.analyze_all()
        return project
