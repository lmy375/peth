import json
import os
import re
import time

import requests
from web3 import Web3

from ..core.config import config


class ScanAPI(object):

    cache = {}

    def __init__(
        self, api_url, api_key=None, chain_id=None, api_key_env=None, use_v2=None
    ) -> None:
        """
        Do NOT use this, use get_or_create instead to
        bypass API rate.

        Args:
            api_url: The base API URL for the blockchain explorer
            api_key: Optional API key. If not provided, will try to get from environment variables.
            chain_id: Chain ID for v2 API support
            api_key_env: Environment variable name for API key
            use_v2: Force use of v2 API if True, v1 if False, auto-detect if None
        """
        self.api_url = api_url
        self._api_key = api_key
        self.chain_id = chain_id
        self.api_key_env = api_key_env
        self.use_v2 = use_v2

        # Auto-detect v2 if not specified
        if self.use_v2 is None and api_url:
            # Use v2 for Etherscan domains when chain_id is available
            self.use_v2 = "etherscan.io" in api_url and chain_id is not None

        self._cache_path = os.path.join(
            config.contracts_cache_path,
            re.findall("//(.*)?/", api_url)[0] if api_url else "unknown",
        )
        if not os.path.exists(self._cache_path):
            os.makedirs(self._cache_path)

        self._source_path = os.path.join(
            config.sources_path,
            re.findall("//(.*)?/", self.api_url)[0] if self.api_url else "unknown",
        )

    @classmethod
    def get_or_create(
        cls, api_url, api_key=None, chain_id=None, api_key_env=None, use_v2=None
    ):
        # Use api_url + api_key + chain_id as cache key to support different configurations
        cache_key = (
            f"{api_url}:{api_key}:{chain_id}:{use_v2}"
            if api_key or chain_id
            else api_url
        )
        if cache_key not in cls.cache:
            cls.cache[cache_key] = cls(api_url, api_key, chain_id, api_key_env, use_v2)
        return cls.cache[cache_key]

    @classmethod
    def get_or_create_by_chain(cls, chain, api_key=None, use_v2=None):
        assert (
            chain in config.chains.keys()
        ), f"Invalid chain {chain}. See {config.chains_path}."

        chain_config = config.chains[chain]

        # Support both old list format and new dict format
        if isinstance(chain_config, list):
            # Old format: [rpc_url, scan_url, address_url, ...]
            api_url = chain_config[1]
            # Extract api_key_env and chain_id from chain config if available
            api_key_env = None
            chain_id = None
            for item in chain_config:
                if isinstance(item, dict):
                    if "api_key_env" in item:
                        api_key_env = item["api_key_env"]
                    elif "chain_id" in item:
                        chain_id = item["chain_id"]
        else:
            # New format: {rpc_url: ..., scan_url: ..., address_url: ..., api_key_env: ..., chain_id: ...}
            api_url = chain_config["scan_url"]
            api_key_env = chain_config.get("api_key_env")
            chain_id = chain_config.get("chain_id")

        return ScanAPI.get_or_create(api_url, api_key, chain_id, api_key_env, use_v2)

    @classmethod
    def get_source_by_chain(cls, chain, addr, api_key=None):
        return ScanAPI.get_or_create_by_chain(chain, api_key).get_source(addr)

    @classmethod
    def get_or_create_v2(cls, chain_id, api_key=None):
        """
        Create a v2 API instance for any supported chain using Etherscan v2 API.

        Args:
            chain_id: The chain ID (e.g., 1 for Ethereum, 56 for BSC, 137 for Polygon)
            api_key: Etherscan API key. If not provided, will use ETHERSCAN_API_KEY env var.

        Returns:
            ScanAPI instance configured for v2 API
        """
        # v2 API doesn't need a specific API URL as it uses the unified endpoint
        api_url = "https://api.etherscan.io/v2/api"
        api_key_env = "ETHERSCAN_API_KEY"

        return cls.get_or_create(api_url, api_key, chain_id, api_key_env, use_v2=True)

    @classmethod
    def get_v2_chainlist(cls, api_key=None):
        """
        Get the list of chains supported by Etherscan v2 API.

        Args:
            api_key: Etherscan API key. If not provided, will use ETHERSCAN_API_KEY env var.

        Returns:
            List of chain information dictionaries or None if failed
        """
        if not api_key:
            api_key = os.environ.get("ETHERSCAN_API_KEY", "")

        if not api_key:
            return None

        try:
            url = f"https://api.etherscan.io/v2/chainlist?apikey={api_key}"
            response = requests.get(url, timeout=10)
            data = response.json()

            if data.get("result"):
                return data["result"]
            return None
        except Exception as e:
            print(f"Failed to fetch v2 chainlist: {e}")
            return None

    def _get_api_key(self):
        """Get API key from environment variable based on the API URL or api_key_env."""
        if self._api_key:
            return self._api_key

        # First try to use api_key_env from chains.yaml
        if self.api_key_env:
            self._api_key = os.environ.get(self.api_key_env, "")
            if self._api_key:
                return self._api_key

        # If using v2 API with Etherscan, always use ETHERSCAN_API_KEY
        if self.use_v2 and self.api_url and "etherscan.io" in self.api_url:
            self._api_key = os.environ.get("ETHERSCAN_API_KEY", "")
            return self._api_key

        # Fallback to URL-based detection for backward compatibility
        if self.api_url:
            if "etherscan.io" in self.api_url:
                self._api_key = os.environ.get("ETHERSCAN_API_KEY", "")
            elif "bscscan.com" in self.api_url:
                self._api_key = os.environ.get("BSCSCAN_API_KEY", "")
            elif "polygonscan.com" in self.api_url:
                self._api_key = os.environ.get("POLYGONSCAN_API_KEY", "")
            elif "arbiscan.io" in self.api_url:
                self._api_key = os.environ.get("ARBISCAN_API_KEY", "")
            elif "snowtrace.io" in self.api_url:
                self._api_key = os.environ.get("SNOWTRACE_API_KEY", "")
            else:
                # Generic fallback
                self._api_key = os.environ.get("SCAN_API_KEY", "")

        return self._api_key

    def _build_url(self, base_url):
        """Build URL with API key if available, supporting both v1 and v2 APIs."""
        api_key = self._get_api_key()

        # For v2 API, use Etherscan v2 endpoint with chain ID
        if self.use_v2 and self.chain_id is not None:
            # If base_url is already v2 API URL, just ensure chain ID and API key
            if "api.etherscan.io/v2/api" in base_url:
                import urllib.parse

                parsed = urllib.parse.urlparse(base_url)
                params = urllib.parse.parse_qs(parsed.query)

                # Rebuild with chain ID
                v2_params = [f"chainid={self.chain_id}"]

                # Add existing params (excluding chainid and apikey)
                for key, values in params.items():
                    if key not in ["chainid", "apikey"]:
                        for value in values:
                            v2_params.append(f"{key}={value}")

                # Add API key
                if api_key:
                    v2_params.append(f"apikey={api_key}")

                return f"https://api.etherscan.io/v2/api?{'&'.join(v2_params)}"
            else:
                # Convert v1 URL to v2 format
                import urllib.parse

                parsed = urllib.parse.urlparse(base_url)
                params = urllib.parse.parse_qs(parsed.query)

                # Build v2 URL
                v2_url = "https://api.etherscan.io/v2/api"
                v2_params = [f"chainid={self.chain_id}"]

                # Add existing params
                for key, values in params.items():
                    if key != "apikey":  # Skip apikey as we'll add it later
                        for value in values:
                            v2_params.append(f"{key}={value}")

                # Add API key if available
                if api_key:
                    v2_params.append(f"apikey={api_key}")

                return f"{v2_url}?{'&'.join(v2_params)}"

        # For v1 API, use the original logic
        if api_key:
            # Check if URL already has parameters
            separator = "&" if "?" in base_url else "?"
            return f"{base_url}{separator}apikey={api_key}&"
        return base_url

    def _cache_get(self, id: str):
        path = os.path.join(self._cache_path, id)
        if os.path.exists(path):
            return open(path).read()
        else:
            return None

    def _cache_set(self, id: str, data: str):
        path = os.path.join(self._cache_path, id)
        open(path, "w").write(data)

    def get(self, url):
        try:
            r = requests.get(url)
            d = r.json()

            # retry.
            if "Max rate limit reached" in d["result"]:
                # API request limit.
                time.sleep(config.scan_api_interval)
                return self.get(url)

            assert d["status"] == "1", d
            assert type(d["result"]) is list, d["result"]
            return d["result"]
        except Exception as e:
            print("[!] Etherscan API fail.", e, url)
            return None

    def get_contract_info(self, addr, auto_proxy=True, depth=0):
        addr = addr.lower()

        # Try cache load.
        d = self._cache_get(addr + ".json")
        if d:
            d = json.loads(d)
        else:
            base_url = f"{self.api_url}{'?' if not self.api_url.endswith('?') else ''}module=contract&action=getsourcecode&address={addr}"
            url = self._build_url(base_url)
            d = self.get(url)
            if d is None:
                return None

            d = d[0]  # The first.
            # Un-verified.
            if not d.get("ContractName", None):
                return None

            if d:
                self._cache_set(addr + ".json", json.dumps(d))

        # Handle proxy
        if d:
            if "Implementation" in d:
                impl = d["Implementation"]
                if auto_proxy and depth < 4:
                    if Web3.is_address(impl) and impl.lower() != addr.lower():
                        return self.get_contract_info(impl, depth=depth + 1)
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
        if not Web3.is_address(addr):
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

            except Exception:
                print("[!] get_source: SourceCode may be not properly handled.")
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
        # Protect from path travel attack.
        path = path.strip("/")
        path = path.strip("~")
        path = path.replace("..", "_")
        return path

    def download_source(self, addr, output_dir=None):

        if not output_dir:
            output_dir = os.path.join(self._source_path, addr)

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

            open(path, "w").write(src)

        return path_list

    def get_standard_json_input(self, addr):
        info = self.get_contract_info(addr)

        if not info:
            return

        contract_name = info["ContractName"]
        if not contract_name:  # Skip un-verified contract.
            return

        version = info["CompilerVersion"]
        if "vyper" in version:  # Skip vyper.
            return

        version = re.findall(r"\d+\.\d+\.\d+", version)[0]
        optimization_used = info["OptimizationUsed"] == "1"
        if optimization_used:
            runs = int(info["Runs"])
            opt = {"enabled": True, "runs": runs}
        else:
            opt = {"enabled": False}

        src: str = info["SourceCode"]
        if src.startswith("{{"):  # Json input format.
            return contract_name, version, json.loads(src[1:-1])

        if src.startswith("{"):  # Multi-files.
            src = json.loads(src)
        else:  # Single file.
            src = {f"{contract_name}.sol": {"content": src}}

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
                },
            },
        }
        return contract_name, version, json_input

    def download_json(self, addr, output_dir=None):
        if not output_dir:
            output_dir = os.path.join(
                config.output_path, "json", re.findall("//(.*)?/", self.api_url)[0]
            )

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        ret = self.get_standard_json_input(addr)
        if ret:
            contract_name, version, json_input = ret
            name = f"{contract_name}_{version}_{addr}.json"
            final_path = os.path.join(output_dir, name)
            json.dump(json_input, open(final_path, "w"))
            return final_path

    def get_txs_by_account(
        self,
        sender,
        startblock=None,
        endblock=None,
        count=10,
        reverse=False,
        internal=False,
    ):
        base_url = f"{self.api_url}{'?' if not self.api_url.endswith('?') else ''}module=account"

        if internal:
            base_url += "&action=txlistinternal"
        else:
            base_url += "&action=txlist"

        base_url += f"&address={sender}"

        if startblock is not None:
            base_url += f"&startblock={startblock}"
        if endblock is not None:
            base_url += f"&endblock={endblock}"

        base_url += f"&page=1&offset={count}"

        if reverse:
            base_url += "&sort=desc"
        else:
            base_url += "&sort=asc"

        url = self._build_url(base_url)
        txs = self.get(url)
        return txs

    def get_first_tx(self, addr: str):
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

            if (
                int(tx["blockNumber"]) <= int(first_tx["blockNumber"])
                and tx["from"] != addr
            ):
                return True, tx
        except Exception:
            pass

        return None, None
