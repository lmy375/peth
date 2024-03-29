import json
import os
from typing import Any, Union

from .abi import ABI, ABIFunction


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

    def call(self, *args: Any, **kwds: Any) -> Any:
        tx = self.build(*args, **kwds)
        output = self.contract.web3ex.eth_call_raw(
            tx["to"], tx["data"], value=tx["value"]
        )
        return self.abi.decode_output(output)

    def send(self, *args: Any, **kwds: Any) -> Any:
        tx = self.build(*args, **kwds)
        wait = kwds.get("wait", 10)
        return self.contract.web3ex.send_transaction(
            tx["data"], tx["to"], tx["value"], wait=wait
        )

    def build(self, *args: Any, **kwds: Any) -> dict:
        to = self.contract.address
        data = self.abi.encode_input(args)
        value = kwds.get("value", 0)
        if value != 0:
            assert self.abi.is_payable, "Value not allowed for non-payable function"
        return {"to": to, "data": data, "value": value}


class Contract(object):

    def __init__(self, web3ex, address: str, abi: Union[str, dict, ABI]) -> None:
        self.web3ex = web3ex
        self.address: str = address

        assert abi is not None, ValueError("ABI not provided")
        self.abi: ABI = self._load_abi(abi)

        self._bind_methods()

    @property
    def sender(self):
        return self.web3ex.sender

    @property
    def signer(self):
        return self.web3ex.signer

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
            setattr(self, name, ContractFunction(self, func))


class ERC20(Contract):

    def __init__(self, web3ex, address: str) -> None:
        super().__init__(
            web3ex,
            address,
            [
                "totalSupply() -> (uint256) view",
                "balanceOf(address) -> (uint256) view ",
                "allowance(address, address) -> (uint256) view",
                "name() -> (string) view",
                "symbol() -> (string) view",
                "decimals() -> (uint8) view",
                "transfer(address, uint256) nonpayable",
                "approve(address, uint256) nonpayable",
            ],
        )
