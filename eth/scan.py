import time
import requests
import json

from core.config import config, DEFAULT_API_INTERVAL

class ScanAPI(object):

    cache = {}

    def __init__(self, scan_url) -> None:
        """
        Do NOT use this, use get_or_create instead to 
        bypass API rate.
        """
        self.scan_url = scan_url
        self.has_api_key = 'apikey' in scan_url
        self._last_scan_call = 0

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
            return d["result"][0]
        except Exception as e:
            print("[!] Etherscan API fail.", e, url)
            return None      

    def get_contract_info(self, addr):
        url = f"{self.scan_url}module=contract&action=getsourcecode&address={addr}"
        return self.get(url)

    def get_abi(self, addr):
        return self.get_contract_info(addr)["ABI"]

    def get_source(self, addr):
        ret = ""
        info = self.get_contract_info(addr)

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

            except Exception as e:
                print('[!] get_source: SourceCode may be not properly handled.')
                ret += "%s\n" % src

        if "AdditionalSources" in info:
            for item in info["AdditionalSources"]:
                ret += "//%s\n" % item["Filename"]
                ret += "%s\n" % item["SourceCode"] 
        return ret

    @classmethod
    def get_or_create(cls, scan_url):
        if scan_url not in cls.cache:
            cls.cache[scan_url] = cls(scan_url)
        return cls.cache[scan_url]

    @classmethod
    def get_source_by_chain(cls, chain, addr):
        assert chain in config.keys(), f"Invalid chain {chain}. See config.json."
        return ScanAPI.get_or_create(config[chain][1]).get_source(addr)    
