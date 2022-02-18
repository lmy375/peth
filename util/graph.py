import json


class ERC20Contract(object):

    def __init__(self, contract_name, contract) -> None:
        self.contract_name = contract_name
        self.caller = contract.caller
        try:
            self.name = self.caller.name()
        except Exception as e:
            self.name = contract_name

        try:
            self.symbol = self.caller.symbol()
        except Exception as e:
            self.symbol = self.name

        self.decimals = self.caller.decimals()
        self.totalSupply = self.caller.totalSupply()/(10**self.decimals)

    def balanceOf(self, addr):
        return self.caller.balanceOf(addr)/(10**self.decimals)

    def __str__(self):
        return f"{self.name}({self.symbol}) {self.totalSupply}*(10**{self.decimals})"


class ContractRelationGraph(object):

    # for: http://relation-graph.com/#/options-tools

    def __init__(self, addr, peth) -> None:

        self.data = {
            "rootId": addr,
            "nodes": [
                # {id, text}
            ],
            "links": [
                # {from, to, text, color}
            ],
        }

        self._ids = set()
        self.root = addr

        self.peth = peth
        self.web3 = peth.web3

        self.addrs = {} # addr => name
        self.erc20s = {} # addr => web3 contract instance

    def get_contract_info(self, addr):
        return self.peth.scan.get_contract_info(addr)

    def _add_node(self, **kwargs):
        assert "id" in kwargs, "id not exist."

        node = {}
        for k, v in kwargs.items():
            node[k] = str(v)

        if node["id"] not in self._ids:
            self._ids.add(node["id"])
            self.data["nodes"].append(node)

    def _add_link(self, **kwargs):
        assert "from" in kwargs, "from not exist."
        assert "to" in kwargs, "from not exist."
        link = {}
        for k, v in kwargs.items():
            link[k] = str(v)

        self.data["links"].append(link)

    def add_contract_or_eoa(self, addr, name):
        self._add_node(
            id=addr, text=name, fontColor="rgba(255, 140, 0, 1)",
        )
        self.addrs[addr] = name

    def add_view(self, addr, name, value):
        id = f"{addr}_{name}"
        text = f"{name} = {value}"
        self._add_node(id=id, text=text, nodeShape=1, opacity=0.75)
        self._add_link(**{"from": addr, "to": id})

    def add_relation(self, _from, to, text):
        self._add_link(**{"from": _from, "to": to, "text": text})

    def dump(self, file=None):
        if file:
            json.dump(self.data, open(file, "w"))
        else:
            return json.dumps(self.data)

    def print_assets(self):
        print("Assets of related addresses.")
        for addr, name in self.addrs.items():
            print(f"{name} {addr}:")
            b = self.web3.eth.get_balance(addr)
            if b:
                print("- %s Wei( %0.4f Ether)" % (b, float(self.web3.fromWei(b, 'ether'))))

            for erc20 in self.erc20s.values():
                amount = erc20.balanceOf(addr)
                if amount == 0:
                    continue

                symbol = erc20.symbol
                total = erc20.totalSupply
                print("- %0.2f %s (%0.2f %%)" % (
                    amount,
                    symbol,
                    amount/total
                ))

    def _add_erc20(self, addr, contract_name, abi, contract):
        if addr in self.erc20s:
            return

        count = 0
        for item in abi:
            if item["type"] == "function" and item["name"] == 'balanceOf':
                count += 1

            if item["type"] == "function" and item["name"] == 'transfer':
                count += 1

            if item["type"] == "function" and item["name"] == 'transferFrom':
                count += 1

            if item["type"] == "function" and item["name"] == 'approve':
                count += 1

        if count == 4:
            self.erc20s[addr] = ERC20Contract(contract_name, contract)
            print("ERC20 Found. ", self.erc20s[addr])

    def _do_visit(self, addr, abi, contract_name, new_contacts, include_view):
        contract = self.web3.eth.contract(address=addr, abi=abi)

        self._add_erc20(addr, contract_name, abi, contract)

        print('=' * 20)
        print(f"{contract_name}({addr}) ABI:")

        for func in contract.all_functions():
            abi = func.abi

            skip = False
            view = True
            if abi["type"] != "function":
                skip = True
            if abi["stateMutability"] != "view":
                skip = True
                view = False
            if abi["inputs"]:  # We have no idea to generate valid inputs now.
                skip = True
            

            name = abi["name"]
            args_sig = ",".join('%s %s' % (i["type"], i["name"]) for i in abi["inputs"])
            return_sig = ",".join('%s %s' % (i["type"], i["name"]) for i in abi["outputs"])
            func_sig = f"{contract_name}.{name}({args_sig})->({return_sig})"
            if view:
                func_sig = '[VIEW] ' + func_sig
            if skip:
                print(func_sig)
                continue

            try:
                ret = func().call()
            except Exception as e:
                print(
                    f"[*] Error in calling {contract_name}.{func.function_identifier}",
                    e,
                )
                continue

            print(f"{func_sig} = {ret}")

            if len(abi["outputs"]) == 1:
                if (
                    abi["outputs"][0]["type"] == "address"
                    and ret != "0x0000000000000000000000000000000000000000"
                ):
                    self.add_relation(contract.address, ret, func.function_identifier)
                    if ret not in self._ids:
                        new_contacts.add(ret)
                else:
                    if include_view:
                        self.add_view(contract.address, func.function_identifier, ret)

            else:
                for i, item in enumerate(abi["outputs"]):
                    if (
                        item["type"] == "address"
                        and ret[i] != "0x0000000000000000000000000000000000000000"
                    ):
                        self.add_relation(
                            contract.address,
                            ret[i],
                            f"{func.function_identifier}[{i}]",
                        )
                        if ret[i] not in self._ids:
                            new_contacts.add(ret[i])
                    else:
                        if include_view:
                            self.add_view(
                                contract.address,
                                f"{func.function_identifier}[{i}]",
                                ret[i],
                            )

    def visit(self, addr, include_view=False):
        if addr in self._ids:
            return

        info = self.get_contract_info(addr)
        if info is None:
            print("[*] get_contract_info fail.")
            return

        contract_name = info.get("ContractName", addr)
        if not contract_name:
            contract_name = addr

        abi = info.get("ABI", "Contract source code not verified")

        if "Proxy" in info:
            if info["Proxy"] != "0" and info["Implementation"]:
                proxy_addr = info["Implementation"]
                proxy_info = self.get_contract_info(proxy_addr)
                proxy_name = proxy_info["ContractName"]
                print(f"[*] Proxy found. {contract_name}({addr})=>{proxy_name}({proxy_addr})")

                contract_name = proxy_name or contract_name
                abi = proxy_info.get('ABI', abi)

        self.add_contract_or_eoa(addr, contract_name)

        if abi == "Contract source code not verified":
            print(f"[*] Maybe EOA or un-verified contract: {contract_name} {addr}")
            return
        try:
            abi = json.loads(abi)
        except Exception as e:
            print("[!] ABI not valid JSON", e, abi)
            return

        new_contacts = set()

        self._do_visit(addr, abi, contract_name, new_contacts, include_view)

        for addr in new_contacts:
            self.visit(addr)
