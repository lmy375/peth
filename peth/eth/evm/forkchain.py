import atexit
import os
import pickle

from web3 import Web3

from peth import Peth
from peth.core.config import config


class ForkChain(object):

    def __init__(self, web3: Web3, fix_block_number: int = 0) -> None:
        self.web3: Web3 = web3

        if fix_block_number:
            self.fix_block_number = fix_block_number
        else:
            self.fix_block_number = web3.eth.block_number  # Fix to current.

        self.chainid = web3.eth.chain_id
        self.block = web3.eth.get_block(self.fix_block_number - 1)

        if not os.path.exists(config.evm_cache_path):
            os.makedirs(config.evm_cache_path)

        self._cache_file_name = os.path.join(
            config.evm_cache_path,
            "fork_%s_%s.pickle" % (self.chainid, self.fix_block_number),
        )

        self.addresses = {}

        self.balances = {}
        self.nonces = {}
        self.codes = {}
        self.storage = {}

        # Auto save.
        atexit.register(self.save)

        loaded = self.load()
        if loaded:
            return

    def load(self) -> bool:
        # TODO: Use faster method.
        if os.path.exists(self._cache_file_name):
            [
                self.addresses,
                self.balances,
                self.nonces,
                self.codes,
                self.storage,
                self.chainid,
                self.block,
            ] = pickle.load(open(self._cache_file_name, "rb"))
            return True
        else:
            return False

    def save(self):
        data = [
            self.addresses,
            self.balances,
            self.nonces,
            self.codes,
            self.storage,
            self.chainid,
            self.block,
        ]
        pickle.dump(data, open(self._cache_file_name, "wb"))

    def get_balance(self, address: str) -> int:
        address = Web3.to_checksum_address(address)
        if address in self.balances:
            return self.balances[address]

        balance = self.web3.eth.get_balance(address, self.fix_block_number)
        self.balances[address] = balance
        return balance

    def get_nonce(self, address: str) -> int:
        address = Web3.to_checksum_address(address)
        if address in self.nonces:
            return self.nonces[address]

        nonce = self.web3.eth.get_transaction_count(address, self.fix_block_number)
        self.nonces[address] = nonce
        return nonce

    def get_code(self, address: str) -> bytes:
        address = Web3.to_checksum_address(address)
        if address in self.codes:
            return self.codes[address]

        code = bytes(self.web3.eth.get_code(address, self.fix_block_number))
        self.codes[address] = code
        return code

    def get_storage(self, address: str, slot: int) -> int:
        address = Web3.to_checksum_address(address)
        if address in self.storage:
            if slot in self.storage[address]:
                return self.storage[address][slot]

        value = self.web3.eth.get_storage_at(address, slot, self.fix_block_number)
        value = self.web3.to_int(value)
        if address not in self.storage:
            self.storage[address] = {}
        self.storage[address][slot] = value
        return value

    @classmethod
    def fork(cls, chain, block_number=0) -> "ForkChain":
        web3 = Peth.get_or_create(chain).web3
        return cls(web3, block_number)
