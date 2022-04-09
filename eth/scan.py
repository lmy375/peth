import time
import requests
import json
import os
import re

from web3 import Web3

from core.config import chain_config, DEFAULT_API_INTERVAL, CACHE_PATH

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

            # https://api.cronoscan.com/api?module=contract&action=getsourcecode&address=0x3eB63cff72f8687f8DE64b2f0e40a5B950000000
            # ! cronoscan bug !
            if d["ContractName"] == "CrowToken":
                return None
            
            # Un-verified.
            if d["ContractName"] == "":
                return None

            if d: 
                self._cache_set(addr + ".json", json.dumps(d))

        # Handle proxy
        if d:
            impl = d["Implementation"]
            if auto_proxy and Web3.isAddress(impl): # Proxy found.
                return self.get_contract_info(impl)
        return d

    def get_abi(self, addr):
        info = self.get_contract_info(addr)
        if info is None:
            return None

        abi = info["ABI"]
        if abi == "Contract source code not verified":
            return None
        else:
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

    def get_source(self, addr):
        ret = ""
        info = self.get_contract_info(addr)
        assert info, "ScanAPI.get_source: get_contract_info failed."

        if "SourceCode" in info:
            src = info["SourceCode"]
            try:
                if src.startswith("{"):
                    tmp = src
                    if src.startswith("{{"):
                        tmp = src.replace('{{', "{").replace("}}", '}')
                    sources = json.loads(tmp)
                    if "sources" in sources:
                        sources = sources["sources"]
                    for name in sources:
                        ret += "//%s\n" % name
                        ret += "%s\n" % sources[name]["content"]
                else:
                    ret += "%s\n" % src

            except Exception as e:
                print('[!] get_source: SourceCode may be not properly handled.')
                ret += "%s\n" % src

        if "AdditionalSources" in info:
            for item in info["AdditionalSources"]:
                ret += "//%s\n" % item["Filename"]
                ret += "%s\n" % item["SourceCode"] 
        
        assert ret, "ScanAPI.get_source: source not found in info: %s" % (list(info))
        return ret

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

    @classmethod
    def get_or_create(cls, api_url):
        if api_url not in cls.cache:
            cls.cache[api_url] = cls(api_url)
        return cls.cache[api_url]

    @classmethod
    def get_source_by_chain(cls, chain, addr):
        assert chain in chain_config.keys(), f"Invalid chain {chain}. See config.json."
        return ScanAPI.get_or_create(chain_config[chain][1]).get_source(addr)    
