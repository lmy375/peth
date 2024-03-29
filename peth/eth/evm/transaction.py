from typing import Optional

from ..opcodes import OpCode


class Transaction(object):
    id = 0

    VIEW = "View"
    CALL = "Call"
    LIBRARY = "Library"
    TRANSFER = "Transfer"

    def __init__(
        self,
        sender: str = None,
        to: str = None,
        value: int = 0,
        data: bytes = b"",
        code_address: Optional[str] = None,
    ) -> None:
        # Transaction
        self.sender = sender
        self.to = to  # the storage address.
        self.value = value
        self.data = data
        self.gasprice = 100
        self.gas = 100000

        # Internal transaction.
        self._origin = None
        self.depth = 1

        # Internal transaction return.
        self.returndata = b""

        # True only for STATICCALL
        self.static = False

        # False only for DELEGATECALL
        self.do_transfer = True

        # Only for CREATE2
        self.salt = None

        # Used for CALLCODE and DELEGATECALL
        if code_address:
            self._code_address = code_address
        else:
            # Default None for CALL and STATICALL
            # Use `to` as fallback.
            self._code_address = None

        # For debug.
        self.op = None
        self.id = Transaction.id
        Transaction.id += 1
        self.result = None

    @property
    def is_internal_tx(self) -> bool:
        return self.depth > 1

    def __str__(self) -> str:
        return self.to_string()

    def to_string(self, ins=None):
        buf = f"[TX {self.depth}-{self.id}]"
        if self.op:
            buf += f" {self.op}"
        if ins:
            buf += f" {ins.get_address_name(self.sender)} -> {ins.get_address_name(self.to)}"
        else:
            buf += f" {self.sender} -> {self.to}"
        if self.op in [OpCode.CALLCODE, OpCode.DELEGATECALL]:
            buf += f"[{self.code_address}]"

        if self.value > 10**16:
            buf += " (%0.2f eth)" % (self.value / (10**18))
        elif self.value:
            buf += " (%d wei)" % self.value

        if self.data:
            data = self.data[:4]
            buf += " %s" % data.hex()
            if len(data) < len(self.data):
                buf += "..."
        return buf

    @property
    def origin(self):
        if self._origin is None:
            return self.sender
        else:
            return self._origin

    @origin.setter
    def origin(self, value: str):
        self._origin = value

    @property
    def code_address(self):
        if self._code_address is None:
            return self.to
        else:
            return self._code_address

    @code_address.setter
    def code_address(self, value: str):
        self._code_address = value

    def create_internal_tx(
        self,
        op: OpCode,
        to: str = None,
        value: int = 0,
        data: bytes = b"",
        gas: Optional[int] = None,
    ):
        tx = Transaction()

        tx.data = data

        if op in [OpCode.CALLCODE, OpCode.DELEGATECALL]:
            tx.to = self.to  # Keep the storage address unchanged.
            tx.code_address = to  # And use the `to` code.
        elif op is [OpCode.CREATE, OpCode.CREATE2]:
            tx.to = None
        else:
            tx.to = to

        tx.op = op

        if op is OpCode.DELEGATECALL:
            # Keep msg.sender and msg.value unchanged.
            tx.sender = self.sender
            tx.value = self.value
            tx.do_transfer = False
        else:
            tx.sender = self.to
            tx.value = value

        if op is OpCode.STATICCALL:
            tx.static = True
        else:
            # Keep static unchanged.
            tx.static = self.static

        tx.gasprice = self.gasprice

        if gas is None:
            tx.gas = self.gas
        else:
            tx.gas = gas

        tx.origin = self.origin
        tx.depth = self.depth + 1

        tx.returndata = b""
        return tx

    @property
    def call_type(self):
        if self.op is OpCode.STATICCALL:
            return Transaction.VIEW

        if self.op in [OpCode.CALLCODE, OpCode.DELEGATECALL]:
            return Transaction.LIBRARY

        if self.data:
            return Transaction.CALL
        else:
            return Transaction.TRANSFER
