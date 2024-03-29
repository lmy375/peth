import json
import os
from typing import Any, Union

from ..abi import ABI, ERC20_ABI, ABIFunction
from .chain import Chain
from .exceptions import TransactionRevert
from .transaction import Transaction


class ContractFunction(object):

    def __init__(self, contract: "Contract", abi: ABIFunction) -> None:
        self.contract = contract
        self.abi = abi

    @property
    def name(self):
        return self.abi.name

    def __repr__(self):
        return f"Function({self.abi})"

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        if self.abi.is_view:
            return self.call(*args, **kwds)
        else:
            return self.send(*args, **kwds)

    def run_tx(self, tx, allow_revert=False):
        tx = Transaction(tx["from"], tx["to"], tx.get("value", 0), tx["data"])
        r = self.contract.chain.apply_transaction(tx)
        if not allow_revert and not r.success:
            raise TransactionRevert(r)
        return r

    def call(self, *args: Any, **kwds: Any) -> Any:
        tx = self.build(*args, **kwds)
        output = self.run_tx(tx).returndata
        return self.abi.decode_output(output)

    def send(self, *args: Any, **kwds: Any) -> Any:
        tx = self.build(*args, **kwds)
        return self.run_tx(tx, True)

    def build(self, *args: Any, **kwds: Any) -> dict:
        to = self.contract.address
        sender = self.contract.sender
        data = self.abi.encode_input(args)
        value = kwds.get("value", 0)
        if value != 0:
            assert self.abi.is_payable, "Value not allowed for non-payable function"
        return {"to": to, "from": sender, "data": data, "value": value}


class Contract(object):
    def __init__(
        self,
        to: str = None,
        abi: Union[str, dict, ABI] = [],
        sender: str = None,
        deploycode=None,
        value: int = 0,
        chain: Chain = None,
    ) -> None:
        if chain:
            self.chain = chain
        else:
            self.chain = Chain.default

        if sender:
            self.sender = sender
        else:
            self.sender = self.chain.attacker

        if deploycode:
            tx = Transaction(self.sender, None, value, deploycode)
            r = self.chain.apply_transaction(tx)
            self.address = r.created_contract
        else:
            assert to, "either `deploycode` or `to` must be provided."
            self.address = to

        assert abi is not None, ValueError("ABI not provided")
        self.abi: ABI = self._load_abi(abi)

        self._bind_methods()

    def _load_abi(self, abi: Union[str, list, ABI]):
        """
        abi:
            str: ABI file name.
            str: JSON string.
            list: ABI list.
            ABI: ABI object
        """
        if type(abi) is str:
            if os.path.exists(abi):
                abi = open(abi).read()

            abi = json.loads(abi)
            return ABI(abi)
        elif type(abi) is list:
            return ABI(abi)
        elif isinstance(abi, ABI):
            return abi
        else:
            raise TypeError(f"Invalid ABI type {type(abi)}")

    def __getitem__(self, key) -> ContractFunction:
        func = self.abi[key]
        return ContractFunction(self, func)

    def _bind_methods(self):
        """
        Bind methods to contract attributes to support autocomplete
        in IPython.
        """

        for name, func in self.abi.functions.items():
            if getattr(self, name, None) is None:
                # Do NOT override existing properties.
                setattr(self, name, ContractFunction(self, func))

    def call(self, sig, *args, **kwds):
        f = self.abi.get_func_abi(sig)
        if f is None:
            f = ABIFunction(sig)
        return ContractFunction(self, f).call(*args, **kwds)

    def send(self, sig, *args, **kwds):
        f = self.abi.get_func_abi(sig)
        if f is None:
            f = ABIFunction(sig)

        return ContractFunction(self, f).send(*args, **kwds)


class ERC20(Contract):
    def __init__(
        self,
        to: int = 0,
        sender: int = 0,
        deploycode=None,
        value: int = 0,
        chain: Chain = None,
    ) -> None:
        super().__init__(
            to,
            ERC20_ABI,
            sender,
            deploycode,
            value,
            chain,
        )

    def force_transfer(self, sender, to, amount):
        tmp = self.sender
        self.sender = sender
        try:
            self.transfer(to, amount)
        except Exception as e:
            print("[!] ERC20 force_transfer error", e)
        finally:
            self.sender = tmp  # Reset sender.
