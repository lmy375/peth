import json

from .contract import ERC20_ABI
from .receipt import Receipt
from .transaction import Transaction


class Inspector(object):

    def __init__(self, chain, peth) -> None:
        super().__init__()

        # Including Trasactions and Receipts.
        self._tx_traces = []

        self.related_addresses = set()
        self.called_contracts = set()
        self.created_contracts = set()
        self.erc20_contracts = set()

        self.peth = peth
        self.attach_chain(chain)

    def attach_chain(self, chain):
        self.chain = chain
        self.chain.inspector = self

    def detach(self):
        if self.chain:
            self.chain.inspector = None

    def get_address_name(self, addr, with_address=True):
        if addr == self.chain.attacker:
            return "Attacker"
        if addr == self.chain.whale:
            return "Whale"

        name = self.peth.scan.get_contract_name(addr)
        if name:
            if with_address:
                return f"{name}({addr})"
            else:
                return name

        return addr

    def add_transaction(self, tx: Transaction):
        self._tx_traces.append(tx)

        self.related_addresses.add(tx.sender)
        self.related_addresses.add(tx.to)

        if self.chain.is_contract(tx.to):
            self.called_contracts.add(tx.to)

            selector = tx.data[:4]
            if len(selector) == 4:
                if ERC20_ABI.get_func_abi(selector):
                    self.erc20_contracts.add(tx.to)

    def add_receipt(self, r: Receipt):
        self._tx_traces.append(r)

        if r.created_contract:
            self.created_contracts.add(r.created_contract)

    def print_call_trace(self):
        for i in self._tx_traces:
            if isinstance(i, Transaction):
                print(" " * i.depth + i.to_string(self))
            else:
                assert isinstance(i, Receipt)
                print(" " * i.tx.depth + str(i))

    def print_contracts(self, contract_set):
        for i in contract_set:
            print(self.get_address_name(i))

    def gen_relation_graph(self, file=None):
        # for: http://relation-graph.com/#/options-tools

        def node_id(addr):
            return addr

        def node_text(addr):
            return self.get_address_name(addr, False)  # short

        data = {
            "rootId": None,
            "nodes": [
                # {id, text}
            ],
            "links": [
                # {from, to, text, color}
            ],
        }
        for i in self.related_addresses:
            data["nodes"].append({"id": node_id(i), "text": node_text(i)})

        for tx in self._tx_traces:
            if isinstance(tx, Transaction):
                if data["rootId"] is None and tx.sender:
                    data["rootId"] = node_id(tx.sender)

                link = {"from": node_id(tx.sender), "to": node_id(tx.to)}

                if tx.op:
                    link["text"] = tx.op.mnemonic
                if tx.call_type == Transaction.VIEW:
                    link["color"] = "green"
                elif tx.call_type in [Transaction.CALL, Transaction.TRANSFER]:
                    link["color"] = "blue"
                else:
                    # Transaction.LIBRARY
                    # Use default color.
                    pass

                data["links"].append(link)

        if file:
            json.dump(data, open(file, "w"))
        else:
            print(json.dumps(data))
