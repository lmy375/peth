import copy
import time
from typing import Optional

from .forkchain import ForkChain
from .receipt import Receipt
from .transaction import Transaction
from .utils import (
    USER_1_ADDRESS,
    USER_2_ADDRESS,
    ZERO_ADDRESS,
    generate_contract_address,
    generate_safe_contract_address,
    to_lower_address,
    uint_to_address,
)
from .vm import VM


class Account(object):
    def __init__(self, address: str, balance: int = 0) -> None:
        self.address = to_lower_address(address)
        self.balance = balance
        self.nonce = 0
        self.code = b""
        self.storage = {}
        self.remote = False


class Chain(object):

    debug = False
    trace = False

    default = None

    def __init__(self, fork: ForkChain = None, inspector=None) -> None:

        self.blockhashes = []  # TODO:
        self.coinbase = ZERO_ADDRESS
        self.timestamp = int(time.time())
        self.blocknumber = 10000
        self.difficulty = 10000
        self.gaslimit = 10000
        self.basefee = 10000
        self.chainid = 1

        self.accounts = {}

        self.__snapshots = []

        self.fork = fork
        if fork:  # TODO: cache this.
            self.blocknumber = fork.fix_block_number
            self.chainid = fork.chainid
            self.timestamp = int(fork.block.timestamp)
            self.difficulty = fork.block.difficulty
            self.gaslimit = fork.block.gasLimit
            self.coinbase = int(fork.block.miner, 16)

        self._init_default_accounts()

        # Auto mining new block after each tx.
        self.auto_mining = True

        # Collect Trasactions and Receipts log.
        self.inspector = inspector
        if inspector:
            inspector.attach_chain(self)

    def use_as_default(self):
        """
        Mark this as default chain instance, thus we
        don't have pass `chain` parameter everywhere.
        """
        Chain.default = self

    def _init_default_accounts(self):
        a = self.create_account(USER_1_ADDRESS)
        a.balance = 10**6 * 10**18  # 1M ETH.
        self.attacker = a.address

        a = self.create_account(USER_2_ADDRESS)
        a.balance = 10**6 * 10**18  # 1M ETH.
        self.whale = a.address

    def mine(self):
        self.blocknumber += 1
        self.timestamp += 15

    def snapshot(self) -> int:
        data = dict(self.__dict__)

        # Do NOT snapshot these.
        del data["fork"]
        del data["_Chain__snapshots"]  # __snapshots
        del data["inspector"]

        self.__snapshots.append(copy.deepcopy(data))

        return len(self.__snapshots)

    def revert(self, i=None):
        assert self.__snapshots, "No snapshot found."

        if i is not None:
            assert i < len(self.__snapshots), "Invalid snapshot ID."
            self.__snapshots = self.__snapshots[:i]  # Drop all snapshots after the ID.

        self.__dict__.update(self.__snapshots.pop())

    def commit(self):
        assert self.__snapshots, "No snapshot found."
        self.__snapshots.pop()

    def get_blockhash(self, idx):
        # TODO
        return 0x1111111111

    def create_account(self, address: str) -> Account:
        address = to_lower_address(address)
        assert address not in self.accounts, f"{address} alrealy exists."
        account = Account(address)
        self.accounts[address] = account
        return account

    def get_account(self, address: str) -> Optional[Account]:
        address = to_lower_address(address)
        return self.accounts.get(address)

    def ensure_account(self, address) -> Account:
        address = to_lower_address(address)
        account = self.get_account(address)
        if account is None:
            account = self.create_account(address)

            if self.fork:
                account.balance = self.fork.get_balance(account.address)
                account.nonce = self.fork.get_nonce(account.address)
                account.code = self.fork.get_code(account.address)

                # If anything found on chain, assume this a remote account.
                if account.balance or account.nonce or account.code:
                    account.remote = True

        return account

    def set_balance(self, address: str, amount: int) -> None:
        account = self.ensure_account(address)
        account.balance = amount

    def get_balance(self, address: str) -> int:
        account = self.ensure_account(address)
        return account.balance

    def is_contract(self, address: str) -> bool:
        return bool(self.get_code(address))

    def _transfer_balance(self, sender: str, to: str, amount: int) -> Receipt:
        """
        Transfer ETH between addresses.
        Return True if success.
        Note: This does NOT update nonce.
        """
        sender_balance = self.get_balance(sender)
        if amount > sender_balance:
            return Receipt("Insufficient Funds")

        to_balance = self.get_balance(to)
        self.set_balance(sender, sender_balance - amount)
        self.set_balance(to, to_balance + amount)
        return Receipt()

    def set_storage(self, address: str, slot: int, value: int):
        account = self.ensure_account(address)
        account.storage[slot] = value

    def get_storage(self, address: str, slot: int):
        account = self.ensure_account(address)
        value = account.storage.get(slot)
        if value is None:
            if self.fork and account.remote:
                value = self.fork.get_storage(address, slot)
                account.storage[slot] = value
            else:
                value = 0
        return value

    def set_code(self, address: str, code: bytes) -> None:
        account = self.ensure_account(address)
        account.code = code

    def get_code(self, address: str) -> bytes:
        account = self.ensure_account(address)
        return account.code

    def destruct_contract(self, address: str, beneficiary: int):
        contract = self.ensure_account(address)
        beneficiary = self.ensure_account(beneficiary)

        assert contract.code, "Destruct EOA? %s" % (address)
        amount = self.get_balance(contract.address)
        self._transfer_balance(contract.address, beneficiary.address, amount)

        del self.accounts[address]

    def _create_contract(self, tx: Transaction) -> Receipt:
        """
        Executes the deploy code, set returndata as code to new contract.
        Returns new contract address or 0 for failure.
        """
        assert tx.to is None, "Sending to %#x to create? Should be None" % tx.to
        sender = self.ensure_account(tx.sender)
        if tx.salt is None:
            contract = generate_contract_address(sender.address, sender.nonce)
        else:
            contract = generate_safe_contract_address(sender.address, tx.salt, tx.data)
        # When executing the constructor, the address should be set already.
        tx.to = contract

        r = self._evm_run_transcation(tx, True)
        if r.success:
            self.set_code(contract, r.returndata)
            r.created_contract = contract

            # Update nonce here as internal tx also update nonce.
            sender.nonce += 1

        return r

    def _evm_run_transcation(self, tx: Transaction, create=False) -> Receipt:
        """
        Use EVM to run the transcation which should be a
        contract creating or contract interacting transaction.
        """

        def __run_evm():
            # Transfer should occur before contract running.
            if tx.do_transfer:
                r = self._transfer_balance(tx.sender, tx.to, tx.value)
                if not r.success:
                    return r

            vm = VM(self, tx)
            if create or tx.to == 0:
                assert tx.data, "Creating contract without deploy code?"
                r = vm.execute(tx.data)
            else:
                code = self.get_code(tx.code_address)
                assert code, "Calling EOA? %s" % (uint_to_address(tx.code_address))
                r = vm.execute(code)
            return r

        _ss_count = len(self.__snapshots)
        self.snapshot()

        r = __run_evm()

        # Bind transaction and receipt.
        r.tx = tx
        tx.result = r

        if r.success:
            # No more need last snapshot.
            self.commit()
        else:
            # Revert the world.
            self.revert()

        assert _ss_count == len(self.__snapshots)
        return r

    def apply_transaction(self, tx: Transaction, update_nonce=True) -> Receipt:
        """
        Apply the transaction to chain. Update nonce.
        """

        if self.inspector:
            self.inspector.add_transaction(tx)

        if self.debug:
            print(" " * tx.depth + str(tx))

        sender = self.ensure_account(tx.sender)

        if tx.to:
            to = self.ensure_account(tx.to)
        else:
            to = None

        if to is None:
            # Create contract.
            r = self._create_contract(tx)
            # Nonce already updated in `create_contract`.

        elif to.code:
            # Call contract.
            r = self._evm_run_transcation(tx)
            if update_nonce and r.success:
                sender.nonce += 1
        else:
            # Just transfer.
            assert tx.do_transfer, "Applying non-transfer transfer?"
            r = self._transfer_balance(tx.sender, tx.to, tx.value)
            r.tx = tx  # attach tx.
            if update_nonce and r.success:
                sender.nonce += 1

        if self.inspector:
            self.inspector.add_receipt(r)

        if self.debug:
            print(" " * tx.depth + str(r))

        if self.auto_mining and not tx.is_internal_tx:
            # When an external tx applied, mine a new block.
            self.mine()

        return r
