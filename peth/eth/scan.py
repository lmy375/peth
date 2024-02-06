import time
import requests
import json
import os
import re

from web3 import Web3

from peth.core.config import chain_config, DEFAULT_API_INTERVAL, CACHE_PATH, OUTPUT_PATH

class ScanAPI(object):

    cache = {}

    def __init__(self, api_url) -> None:
        """
        Do NOT use this, use get_or_create instead to 
        bypass API rate.
        """
        self.api_url = api_url
        self.has_api_key = 'apikey' in api_url
        self._last_scan_call = 0

        self._cache_path = os.path.join(CACHE_PATH, re.findall('//(.*)?/', api_url)[0])
        if not os.path.exists(self._cache_path):
            os.makedirs(self._cache_path)

    @classmethod
    def get_or_create(cls, api_url):
        if api_url not in cls.cache:
            cls.cache[api_url] = cls(api_url)
        return cls.cache[api_url]

    @classmethod
    def get_or_create_by_chain(cls, chain):
        assert chain in chain_config.keys(), f"Invalid chain {chain}. See config.json."
        return ScanAPI.get_or_create(chain_config[chain][1])

    @classmethod
    def get_source_by_chain(cls, chain, addr):
        return ScanAPI.get_or_create_by_chain(chain).get_source(addr)

    def _cache_get(self, id: str):
        path = os.path.join(self._cache_path, id)
        if os.path.exists(path):
            return open(path).read()
        else:
            return None

    def _cache_set(self, id: str, data: str):
        path = os.path.join(self._cache_path, id)
        open(path, 'w').write(data)

    def get(self, url):
        # print(url)
        now = time.time()
        if not self.has_api_key:
            interval = now - self._last_scan_call
            if interval < DEFAULT_API_INTERVAL:
                # API request limit.
                time.sleep(DEFAULT_API_INTERVAL - interval)
        try:
            r = requests.get(url)
            self._last_scan_call = time.time()
            d = r.json()

            # retry.
            if "Max rate limit reached" in d["result"]: 
                return self.get(url)

            assert d["status"] == "1", d
            assert type(d["result"]) is list, d["result"]
            return d["result"]
        except Exception as e:
            print("[!] Etherscan API fail.", e, url)
            return None      

    def get_contract_info(self, addr, auto_proxy=True):
        addr = addr.lower()

        # Try cache load.
        d = self._cache_get(addr + ".json")
        if d:
            d = json.loads(d)
        else:
            url = f"{self.api_url}module=contract&action=getsourcecode&address={addr}"
            d = self.get(url)[0] # The first.
            # Un-verified.
            if not d.get("ContractName", None):
                return None

            if d: 
                self._cache_set(addr + ".json", json.dumps(d))

        # Handle proxy
        if d:
            if "Implementation" in d:
                impl = d["Implementation"]
                if auto_proxy and Web3.isAddress(impl) and impl.lower() != addr: # Proxy found.
                    return self.get_contract_info(impl)
        return d

    def get_abi(self, addr) -> list:
        """
        If contract not verified, return None.
        (Unlikely) If returns invalid json, return the string.
        """
        info = self.get_contract_info(addr)
        if info is None:
            return None

        abi = info["ABI"]
        if abi == "Contract source code not verified":
            return None
        else:
            try:
                return json.loads(abi)
            except json.JSONDecodeError:
                return abi

    def get_contract_name(self, addr):
        if not Web3.isAddress(addr):
            return None 

        info = self.get_contract_info(addr)
        if info is None:
            return None

        return info.get("ContractName", None)

    def get_address_name(self, addr):
        name = self.get_contract_name(addr)
        if name:
            return f"{name}({addr})"
        else:
            return addr

    def get_source(self, addr, flatten=True):
        if flatten:
            ret = ""
        else:
            ret = {}
            
        info = self.get_contract_info(addr)
        assert info, "ScanAPI.get_source: get_contract_info failed."

        if "SourceCode" in info:
            src = info["SourceCode"]
            try:
                if src.startswith("{"):
                    if src.startswith("{{"):
                        src = src[1:-1]
                    sources = json.loads(src)
                    if "sources" in sources:
                        sources = sources["sources"]
                    for name in sources:
                        if flatten:
                            ret += "//%s\n" % name
                            ret += "%s\n" % sources[name]["content"]
                        else:
                            ret[name] = sources[name]["content"]
                else:
                    if flatten:
                        ret += "%s\n" % src
                    else:
                        name = info.get("ContractName", "Main") + ".sol"
                        ret[name] = src

            except Exception as e:
                print('[!] get_source: SourceCode may be not properly handled.')
                ret += "%s\n" % src

        if "AdditionalSources" in info:
            for item in info["AdditionalSources"]:
                if flatten:
                    ret += "//%s\n" % item["Filename"]
                    ret += "%s\n" % item["SourceCode"]
                else:
                    ret[item["Filename"]] = item["SourceCode"]
        
        assert ret, "ScanAPI.get_source: source not found in info: %s" % (list(info))
        return ret

    def _normal_file_path(self, path):
        if path.startswith("@"): # Skip npm package.
            pass
        elif 'contracts/' in path: # locate to contracts dir.
            path = path[path.index('contracts/'):]

        path = path.replace('..', '_') # Protect from path travel attack.
        
        if path.startswith('/'):
            path = path[1:]
        
        return path

    def download_source(self, addr, output_dir=None):

        if not output_dir:
            output_dir = os.path.join(OUTPUT_PATH, "source", re.findall('//(.*)?/', self.api_url)[0], addr)
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        ret = self.get_source(addr, False)
        path_list = []
        for name, src in ret.items():
            path = os.path.join(output_dir, self._normal_file_path(name))
            path_list.append(path)

            parent_dir = os.path.dirname(path)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
                
            open(path, 'w').write(src)
        
        return path_list

    def get_standard_json_input(self, addr):
        info = self.get_contract_info(addr)

        if not info:
            return

        contract_name = info["ContractName"]
        if not contract_name: # Skip un-verified contract.
            return

        version = info["CompilerVersion"]
        if "vyper" in version: # Skip vyper.
            return

        version = re.findall(r'\d+\.\d+\.\d+', version)[0]
        optimization_used = info["OptimizationUsed"] == "1"
        if optimization_used:
            runs = int(info["Runs"])
            opt = {
                "enabled": True,
                "runs":runs
            }
        else:
            opt = {
                "enabled": False
            }

        src = info["SourceCode"]
        if src.startswith("{{"): # Json input format.
            return contract_name, version, json.loads(src[1:-1])

        if src.startswith("{"): # Multi-files.
            src = json.loads(src)
        else: # Single file.
            src = {
                f"{contract_name}.sol": {
                    "content" : src
                }
            }

        json_input = {
            "language": "Solidity",
            "sources": src,
            "settings": {
                "optimizer": opt,
                "outputSelection": {
                    "*": {
                            "*": [
                                "abi",
                                "metadata",
                                "devdoc",
                                "userdoc",
                                "evm.bytecode",
                                "evm.deployedBytecode",
                            ],
                            "": ["ast"],
                    }
                }
            }
        }
        return contract_name, version, json_input

    def download_json(self, addr, output_dir=None):
        if not output_dir:
            output_dir = os.path.join(OUTPUT_PATH, "json", re.findall('//(.*)?/', self.api_url)[0])
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        ret = self.get_standard_json_input(addr)
        if ret:
            contract_name, version, json_input = ret
            name = f"{contract_name}_{version}_{addr}.json"
            final_path = os.path.join(output_dir, name)
            json.dump(json_input, open(final_path, "w"))
            return final_path

    def get_txs_by_account(self, sender, startblock=None, endblock=None, count=10, reverse=False, internal=False):
        url = f"{self.api_url}module=account"
        
        if internal:
            url += "&action=txlistinternal"
        else:
            url += "&action=txlist"
        
        url += f"&address={sender}"
        
        if startblock is not None:
            url += f"&startblock={startblock}"
        if endblock is not None:
            url += f"&endblock={endblock}"
        
        url += f"&page=1&offset={count}"
        
        if reverse:
            url += "&sort=desc"
        else:
            url += "&sort=asc"
        
        txs = self.get(url)
        return txs

    def get_first_tx(self, addr:str):
        addr = addr.lower()
        try:
            txs = self.get_txs_by_account(addr, count=1, internal=False)
            first_tx = txs[0]

            # First tx sent to me.
            if first_tx["to"] == addr and first_tx["from"] != addr:
                return False, first_tx
        except Exception:
            first_tx = None

        # Search internal tx.
        try:
            txs = self.get_txs_by_account(addr, count=1, internal=True)
            tx = txs[0]

            if first_tx is None:
                return True, tx

            if int(tx["blockNumber"]) <= int(first_tx["blockNumber"]) and tx["from"] != addr:
                return True, tx
        except Exception:
            pass 

        return None, None        

