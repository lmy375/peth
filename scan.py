import time
import requests

from config import DEFAULT_API_INTERVAL

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
            assert d["status"] == "1", d
            assert type(d["result"]) is list, d["result"]
            return d["result"][0]
        except Exception as e:
            print("[!]", e)
            return None      

    def get_contract_info(self, addr):
        url = f"{self.scan_url}module=contract&action=getsourcecode&address={addr}"
        return self.get(url)

    def get_abi(self, addr):
        return self.get_contract_info(addr)["ABI"]

    @classmethod
    def get_or_create(cls, scan_url):
        if scan_url not in cls.cache:
            cls.cache[scan_url] = cls(scan_url)
        return cls.cache[scan_url]

