import json
import datetime
import os

from web3 import Web3

from peth.eth.bytecode import Code
from peth.eth.sigs import Signatures, Signature
from peth.eth.utils import ZERO_ADDRESS, selector_to_sigs
from peth.core import config
from peth.core.log import logger
from peth.util.graph import ContractRelationGraph
from peth.util.markdown import make_attr_table, make_table

class AccountAnalysis(object):

    def __init__(self, peth, addr, project=None) -> None:
        self.peth = peth
        self.addr = Web3.toChecksumAddress(addr)
        self.project = project

        self.url = self.peth.get_address_url(self.addr)

        # Values to set after analysis.

        # For analyze_verified_contract(). 
        self.name = None
        self.is_contract = False

        # Only used while is_contract=True
        self.code = None
        self.code_size = 0

        self.verified = False
        self.is_proxy = False
        self.implmentation = None

        self.flatten_source = None

        self.signatures = None
        self.view_sigs = {} # sig => value
        self.uncalled_view_sigs = []
        self.other_sigs = []

        self.properties = {} # name => value

        # For analyze_unverified_contract()
        self.selectors = []
        self.hardcoded_addresses = []

        # For analyze_contract_type()
        self.extra_data = {
            # "owner" : address
            # "proxy" : { }
            # "timelock": { ... }
            # "gnosis": { ... }
            # "oracle": { ... }
        }

        # Risk messages.
        self.risks = []

    def analyze(self):

        logger.debug("Start analyzing %s.", self.addr)

        code_bytes = bytes(self.peth.web3.eth.get_code(self.addr))
        if not code_bytes:
            self.is_contract = False
            self.name = 'EOA'
        
        else:
            # Contract account found.
            self.is_contract = True
            self.code = Code(code_bytes)
            self.code_size = len(code_bytes)

            self.analyze_verified_contract()

            if not self.verified:
                self.name = "Unverified Contract"
            
            self.analyze_unverified_contract()
            self.analyze_extra()

            # Can be slow.
            if config.ENABLE_SLITHER:
                self.analyze_slither()

        logger.debug("%s %s done.", self.addr, self.name)

    def analyze_verified_contract(self):
        info = self.peth.scan.get_contract_info(self.addr, False)
        if info is None:
            self.verified = False
            return
        
        # Process proxy issue.
        impl = info["Implementation"]
        while Web3.isAddress(impl):
            self.is_proxy = True
            self.implmentation = impl
            logger.debug("Proxy found, implmentation %s", impl)
            info = self.peth.scan.get_contract_info(impl, False)
            if info is None:
                self.verified = False
                return
            impl = info["Implementation"]
        
        self.verified = True
        self.name = info["ContractName"]
        logger.debug("Verified contract: %s", self.name)

        # Now we have the real source information.
        abi = info["ABI"]
        assert abi != "Contract source code not verified", "Bug found."
       
        abi = json.loads(abi) # This should be valid json.
        self.signatures = Signatures()

        contract = self.peth.web3.eth.contract(address=self.addr, abi=abi)

        for func in contract.all_functions():
            sig = Signature.from_abi(func.abi)
            self.signatures.add_sig(sig)

            # Classify functions.
            if not (sig.is_view and len(sig.inputs) == 0):
                if sig.is_view:
                    self.uncalled_view_sigs.append(sig)
                else:
                    self.other_sigs.append(sig)
                continue
            
            # Call view functions.
            try:
                ret = func().call()
            except Exception as e:
                # Error in call, just skip this
                continue

            self.view_sigs[sig] = ret
            logger.debug("%s => %s", sig, ret)

            if len(sig.outputs) == 1:
                self.properties[sig.name] = ret
            else:
                for i, item in enumerate(sig.outputs):
                    ret_name = item[0]
                    if ret_name:
                        self.properties[f"{sig.name}.{ret_name}"] = ret[i]
                    else:
                        self.properties[f"{sig.name}[{i}]"] = ret[i]
    
    def analyze_unverified_contract(self):
        addr = self.addr
        if Web3.isAddress(self.implmentation):
            # If this is a proxy, analyze the implmentation code.
            addr = self.implmentation
        self.selectors, self.hardcoded_addresses = self.peth.analyze_bytecode(addr)
        logger.debug("%d selectors, %s hardcode addresses", len(self.selectors), len(self.hardcoded_addresses))


    def __collect_view_values(self, contract, sigs, do_check=True):
        ret = {}
        for sig in sigs:
            s = Signature.from_sig(sig)
            value = self.peth.call_contract(contract, s, silent=True)
            if value is None and do_check:
                return ret
            
            if value is not None:
                ret[s.name] = value
            
        return ret

    def __add_extra_data(self, name, sigs, do_check=True):
        data = self.__collect_view_values(self.addr, sigs, do_check)
        if data:
            self.extra_data[name] = data

    def __analyze_owner(self):
        ret = self.__collect_view_values(self.addr, [
            "owner()->(address)",
            "admin()->(address)",
            "gov()->(address)"
        ], False)
        if ret:
            self.extra_data["owner"] = ret
            for name, addr in ret.items():
                if not self.peth.is_contract(addr):
                    self.risks.append(
                        f"合约 {self.get_addr_md_link(self.addr)} 的 {name} 是 EOA {addr}"
                    )

    def __analyze_erc20(self):
        self.__add_extra_data("erc20",[
            "totalSupply()->(uint256)",
            "name()->(string)",
            "symbol()->(string)",
            "decimals()->(uint8)",
        ])
    
    def __analyze_proxy(self):
        impl = self.peth.web3.eth.get_storage_at(self.addr, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)[12:].hex()
        admin = self.peth.web3.eth.get_storage_at(self.addr, 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103)[12:].hex()
        if impl != ZERO_ADDRESS or admin != ZERO_ADDRESS:
            self.extra_data["proxy"] = {
                "implementation": impl,
                "admin": admin
            }

            self_link = self.get_addr_md_link(self.addr)

            if not self.peth.is_contract(admin):
                self.risks.append(
                    f"Proxy 合约 {self_link} 的 admin 是 EOA {admin}"
                )
            else:
                if self.project:
                    # TODO: recursion may occur here?
                    account = self.project.analyze_one(admin)
                    admin_name = self.project.get_addr_md_link(admin)
                    for name, addr in account.extra_data.get("owner", {}).items():
                        if not self.peth.is_contract(addr):
                            self.risks.append(
                                f"Proxy 合约 {self_link}  的 admin 是 {admin_name}, {admin_name} 的 {name} 是 EOA {addr}"
                            )

    def __analyze_gnosis(self):
        self.__add_extra_data("gnosis", [
            "getThreshold()->(uint)",
            "getOwners()->(address[])"
        ])
    
    def __analyze_timelock(self):
        self.__add_extra_data("timelock", [
            "delay()->(uint)",
            "admin()->(address)",
            "getMinDelay()->(uint)",
            "MINIMUM_DELAY()->(uint)",
            "MAXIMUM_DELAY()->(uint)"
        ])
    
    def __analyze_oracle(self):
        aggr = self.peth.call_contract(self.addr, "aggregator()->(address)", silent=True)
        if aggr:
            data = self.__collect_view_values(aggr, [
                "description()->(string)",
                "owner()->(address)",
                "decimals()->(uint8)",
                "latestAnswer()->(int256)",
                "maxAnswer()->(int192)",
                "minAnswer()->(int192)",
                "transmitters()->(address[])"
            ])
            data["aggregator"] = aggr
            self.extra_data["oracle"] = data

    def analyze_extra(self):
        self.__analyze_owner()
        self.__analyze_erc20()
        self.__analyze_proxy()
        self.__analyze_gnosis()
        self.__analyze_timelock()
        self.__analyze_oracle()


    def analyze_slither(self):
        try:
            from peth.util.slither import slither_from_chain_addr
        except:
            logger.error("Slither not installed: pip install slither-analyzer")
            return
        
        if not self.verified:
            return

        try:
            s = slither_from_chain_addr(self.peth.chain, self.addr)
            contract = s.get_contract_from_name(self.name)[0]
            for f in contract.functions_entry_points:
                sig = self.signatures.find_by_name(f.name)
                if sig and f.modifiers:
                    if not sig.modifiers:
                        sig.modifiers = [i.name for i in f.modifiers]
        except Exception as e:
            logger.error("Slither Error: %s %s", e, self.addr)
            # raise Exception from e

    def related_addresses(self) -> list:
        added_addrs = []
        r = [] # relation, address
        for name, value in self.properties.items():
            if Web3.isAddress(value) and value != ZERO_ADDRESS:
                r.append((name, value))
                added_addrs.append(value)

        for addr in self.hardcoded_addresses:
            if addr not in added_addrs:
                r.append(("hardcode", addr))
        return r

    def __str__(self) -> str:
        return f"{self.name} [{self.addr}]({self.url})"


    def get_addr_md_link(self, addr) -> str:
        if addr != self.addr and self.project:
            return self.project.get_addr_md_link(addr)
        
        if addr == self.addr and self.name:
            txt = f"{self.name}({addr})"
            url = self.url
        else:
            txt = f"{addr}"
            url = self.peth.get_address_url(addr)
        return f"[{txt}]({url})"

    def __json_to_markdown(self, data, depth=0) -> str:
        txt = ''
        if isinstance(data, dict):
            txt += "\n"
            for k, v in data.items():
                txt += " " * 2 * (depth)
                txt += f"- {k}: {self.__json_to_markdown(v, depth+1)}\n"
        elif isinstance(data, (list, tuple)):
            txt += "\n"
            for i in data:
                txt += " " * 2 * (depth)
                txt += f"- {self.__json_to_markdown(i, depth+1)}\n"
        else:
            s = str(data)
            if Web3.isAddress(s):
                s = self.get_addr_md_link(s)
            txt += s
        return txt

    def to_markdown_summary(self) -> str:
        txt = f"[{self.name}({self.addr})]({self.url})"
        for tag in self.extra_data.keys():
            txt += f" `{tag}`"
        return txt

    def to_markdown(self) -> str:

        txt = f"## {self}\n\n"
        if not self.is_contract:
            return txt

        if self.extra_data:
            txt += "\n\n合约提取信息：\n"
            txt += self.__json_to_markdown(self.extra_data)
            txt += "\n\n"

        if self.verified:
            txt += "**合约已开源。** "
            if self.is_proxy:
                txt += f"合约为 Proxy 合约，指向 {self.get_addr_md_link(self.implmentation)}。"
            
            if self.view_sigs or self.uncalled_view_sigs or self.other_sigs:
                txt += "ABI 如下：\n\n"

            if self.view_sigs:
                txt += "无参 View 函数：\n\n"
                data = []
                for sig, value in self.view_sigs.items():
                    if Web3.isAddress(value):
                        value = self.get_addr_md_link(value)
                    elif isinstance(value, bytes):
                        value = value.hex()
                    data.append((sig.name, str(value)))
                txt += make_table(
                    ("名称", "值"),
                    data
                )
                txt += "\n\n"
            
            if self.uncalled_view_sigs:
                # Not so useful information, compact them into single line.
                func_names = ', '.join(sig.name for sig in self.uncalled_view_sigs)
                txt += f"其他 View 函数: {func_names}\n\n"

            if self.other_sigs:
                txt += "Write 函数：\n\n"
                data = []
                for sig in self.other_sigs:
                    data.append((sig.name, sig.modifiers))
                txt += make_attr_table(data)
                txt += "\n\n"
        
        else:
            url = self.peth.get_decompile_url(self.addr)
            txt += f"**合约未开源** ，反编译代码见[此链接]({url})。\n\n"
            if self.selectors:
                txt += "从 bytecode 分析出的 Selectors 如下:\n"
                for selector in self.selectors:
                    sig = '0x' + selector.hex()
                    sigs = selector_to_sigs(sig)
                    sigs = sigs[::-1]
                    txt += f"- {sig} {', '.join(sigs)}\n"

        if self.hardcoded_addresses:

            # Only print addresses not showed in views.
            addrs = []
            for tag, addr in self.related_addresses():
                if tag == 'hardcode':
                    addrs.append(addr)

            if addrs:
                txt += "\n\nbytecode 中发现硬编码的地址。\n"
                for addr in addrs:
                    txt += f"- {self.get_addr_md_link(addr)}\n"

        return txt

        
class Project(object):

    def __init__(self, peth, addresses=[]) -> None:
        self.peth = peth
        self.addresses = [Web3.toChecksumAddress(addr) for addr in addresses]

        self.analyzed = {} # address => AccountAnalysis
        self.accounts = []

    def analyze_all(self) -> None:

        addrs_to_analyze = self.addresses

        i = 1
        while addrs_to_analyze:
            logger.info(f"[{i}] {len(addrs_to_analyze)} addresses to analyze.")
            i += 1
            found_addrs = []

            for addr in addrs_to_analyze:
                addr = Web3.toChecksumAddress(addr)
                if addr in self.analyzed:
                    continue

                account = AccountAnalysis(self.peth, addr, self)
                account.analyze()

                self.analyzed[addr] = account

                for _, addr in account.related_addresses():
                    if addr not in self.analyzed:
                        found_addrs.append(addr)
            
            addrs_to_analyze = found_addrs

        logger.info(f"Project done. {len(self.analyzed)} addresses analyzed.")

    def analyze_one(self, addr) -> AccountAnalysis:
        addr = Web3.toChecksumAddress(addr)
        if addr in self.analyzed:
            return self.analyzed[addr]
        
        account = AccountAnalysis(self.peth, addr, self)
        account.analyze()
        self.analyzed[addr] = account
        return account

    def get_addr_name(self, addr) -> str:
        return self.analyze_one(addr).name

    def get_addr_md_link(self, addr) -> str:
        addr = Web3.toChecksumAddress(addr)
        name = self.get_addr_name(addr)
        txt = f"{name}({addr})"
        url = self.peth.get_address_url(addr)
        return f"[{txt}]({url})"

    def to_markdown(self) -> str:
        txt = "# 整体情况\n\n"

        risks = []
        for a in self.analyzed.values():
            risks += a.risks
        if risks:
            txt += f"风险点：\n"
            for msg in risks:
                txt += f"- {msg}\n"
            txt += "\n"

        verified = []
        unverified = []
        eoas = []
        for account in self.analyzed.values():
            if account.is_contract:
                if account.verified:
                    verified.append(account)
                else:
                    unverified.append(account)
            else:
                eoas.append(account)

        txt += f"输入合约 {len(self.addresses)} 个。"
        txt += f"共发现 {len(self.analyzed)} 个地址。其中\n"
        txt += f"- 开源合约 {len(verified)} 个。\n"
        for account in verified:
            tag = "" if account.addr in self.addresses else "`新发现` "
            txt += f"  - {tag}{account.to_markdown_summary()}\n"
        txt += f"- 未开源合约 {len(unverified)} 个。\n"
        for account in unverified:
            tag = "" if account.addr in self.addresses else "`新发现` "
            txt += f"  - {tag}{account.to_markdown_summary()}\n"  
        txt += f"- EOA {len(eoas)} 个。\n"
        for account in eoas:
            tag = "" if account.addr in self.addresses else "`新发现` "
            txt += f"  - {tag}{account.to_markdown_summary()}\n"
        txt += "\n\n"

        txt += "# 合约详情\n\n"
        for account in verified + unverified:
            txt += account.to_markdown()
            txt += "\n\n"

        txt += "# 合约关系图\n\n"
        txt += "> Open http://relation-graph.com/#/options-tools and paste the json. \n\n"
        txt += "```\n%s\n```\n\n" % self.to_graph().dump()

        return txt

    def to_graph(self) -> ContractRelationGraph:
        g = ContractRelationGraph(self.addresses[0], self.peth)
        for analysis in self.analyzed.values():
            g.add_contract_or_eoa(analysis.addr, analysis.name)
            for name, target in analysis.related_addresses():
                g.add_relation(analysis.addr, target, name)
        return g

    def save(self) -> None:
        time_tag = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
        filename = "Report_%s_%s.md" % (time_tag, self.addresses[0][:10])
        
        report_dir = config.REPORT_PATH
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        path = os.path.join(report_dir, filename)
        open(path, "w").write(self.to_markdown())
        logger.info("Report saved as %s.", path)
