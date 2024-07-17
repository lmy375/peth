import atexit
import json
import os
import re
from typing import Any, Dict, List, Tuple

import requests
from eth_hash.auto import keccak
from web3 import Web3

from peth.core.config import config
from peth.core.log import logger

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
UINT256_MAX = 2**256 - 1


def keccak256(x):
    return keccak(x)


def func_selector(func_sig: str):
    return keccak256(bytes(func_sig, "ascii", "ignore"))[:4]


# from: https://github.com/ethereum/eth-utils/blob/master/eth_utils/abi.py
def collapse_if_tuple(abi: Dict[str, Any]) -> str:
    """
    Converts a tuple from a dict to a parenthesized list of its types.
    >>> from eth_utils.abi import collapse_if_tuple
    >>> collapse_if_tuple(
    ...     {
    ...         'components': [
    ...             {'name': 'anAddress', 'type': 'address'},
    ...             {'name': 'anInt', 'type': 'uint256'},
    ...             {'name': 'someBytes', 'type': 'bytes'},
    ...         ],
    ...         'type': 'tuple',
    ...     }
    ... )
    '(address,uint256,bytes)'
    """
    typ = abi["type"]
    if not isinstance(typ, str):
        raise TypeError(
            "The 'type' must be a string, but got %r of type %s" % (typ, type(typ))
        )
    elif not typ.startswith("tuple"):
        return typ

    delimited = ",".join(collapse_if_tuple(c) for c in abi["components"])
    # Whatever comes after "tuple" is the array dims.  The ABI spec states that
    # this will have the form "", "[]", or "[k]".
    array_dim = typ[5:]
    collapsed = "({}){}".format(delimited, array_dim)

    return collapsed


class SelectorDatabase(object):

    single_instance = None

    def __init__(self) -> None:
        self.db = {}

        if not os.path.exists(config.sig_db_path):
            try:
                logger.info(
                    "Downloading SelectorDatabase from %s ..." % config.sig_db_url
                )
                r = requests.get(config.sig_db_url)
                self.db = r.json()
                logger.info("OK")
            except Exception as e:
                logger.warn("SelectorDatabase init failed. %s" % e)
            logger.debug("Load sig db from %s" % config.sig_db_url)
        else:
            self.db = json.load(open(config.sig_db_path))
            logger.debug("Load sig db from %s" % config.sig_db_path)

        atexit.register(self.save)

    def _normalize_selector(self, selector, with_prefix=False):
        """
        Return hex format.
        """
        if type(selector) is int:
            selector = "%08x" % selector
        elif isinstance(selector, bytes):
            selector = selector.hex()
        else:
            selector = str(selector).lower()

        if selector.startswith("0x"):
            if not with_prefix:
                selector = selector[2:]
        else:
            if with_prefix:
                selector = "0x" + selector

        return selector

    def get_sig_from_selector(self, selector, only_one=False, online=True):

        selector = self._normalize_selector(selector, False)

        # No 0x prefix in DB.
        if selector in self.db:
            sigs = self.db[selector]
            if type(sigs) is str:
                sigs = [sigs]
        elif online:
            sigs = self.get_sig_online(selector, False)
            if sigs:
                self.db[selector] = sigs
        else:
            sigs = []  # Off-line empty result.

        assert type(sigs) is list, "get_sig: should always be list here."
        if only_one:
            if sigs:
                return sigs[0]
            else:
                return None
        else:
            return sigs

    def get_sig_from_text(self, text):
        ret = []  # (selector, [sigs])
        for selector, sig in self.db.items():
            if type(sig) is str:
                sigs = [sig]
            else:
                sigs = sig

            if any([(text in i) for i in sigs]):
                ret.append((selector, sigs))
        return ret

    def get_sig_online(self, selector, only_one=False):

        try:
            # Get sig from sam's db.

            # https://api.openchain.xyz/signature-database/v1/lookup?function=0xa9059cbb&event=0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d&filter=true
            # {
            # "ok": true,
            # "result": {
            #     "event": {
            #     "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d": [
            #         {
            #         "name": "RoleGranted(bytes32,address,address)",
            #         "filtered": false
            #         }
            #     ]
            #     },
            #     "function": {
            #     "0xa9059cbb": [
            #         {
            #         "name": "transfer(address,uint256)",
            #         "filtered": false
            #         }
            #     ]
            #     }
            # }
            # }

            selector = self._normalize_selector(selector, True)
            assert selector.startswith("0x")
            typ = "function" if len(selector) == 10 else "event"

            url = f"https://api.openchain.xyz/signature-database/v1/lookup?&filter=true&{typ}={selector}"
            res = requests.get(url).json()
            results = res["result"][typ][selector]
            if only_one:
                if results:
                    return results[0]["name"]
                else:
                    return None
            else:
                return [i["name"] for i in results]

            # Get sig from 4byte.directory
            # if selector.startswith('0x'):
            #     selector = selector[2:]

            # url = 'https://www.4byte.directory/api/v1/signatures/?hex_signature=%s' % selector
            # r = requests.get(url)
            # results = r.json()["results"]

            # if only_one:
            #     if results:
            #         return results[0]["text_signature"]
            #     else:
            #         return None
            # else:
            #     return [i["text_signature"] for i in results]

        except Exception:
            if only_one:
                return None
            else:
                return []

    def save(self):
        json.dump(self.db, open(config.sig_db_path, "w"))
        logger.debug("Save sig db to %s" % config.sig_db_path)

    @classmethod
    def get(cls):
        if SelectorDatabase.single_instance is None:
            # This can be a little slow as it downloads data from github.
            SelectorDatabase.single_instance = SelectorDatabase()
        return SelectorDatabase.single_instance


def selector_to_sigs(selector, only_one=False):
    """
    selector: with 0x prefix.
    """
    db = SelectorDatabase.get()
    return db.get_sig_from_selector(selector, only_one)


def hex2bytes(hex_data):
    if hex_data.startswith("0x"):
        hex_data = hex_data[2:]
    return bytes.fromhex(hex_data)


def convert_value(value: str):
    """
    Guess value type and convert.
    """
    STR_PATTERN = r"^['\"](.*)['\"]$"
    DEC_PATTERN = r"^\d+$"
    HEX_PATTERN = r"^[0-9A-Fa-fXx]+$"

    if Web3.is_address(value):  # address
        return Web3.to_checksum_address(value)
    elif re.match(STR_PATTERN, value):  # string.
        return re.findall(STR_PATTERN, value)[0]
    elif re.match(DEC_PATTERN, value):  # decimal
        return int(value)
    elif re.match(HEX_PATTERN, value):  # hexcimal
        if len(value) in [64, 66]:
            return hex2bytes(value)
        else:
            return int(value, 16)
    elif value.strip().lower() == "true":
        return True
    elif value.strip().upper() == "false":
        return False
    else:
        return value


def convert_value_list(values):
    return [convert_value(v) for v in values]


def guess_calldata_types(data) -> List[Tuple[str, str, str]]:
    """
    data: hex data without selector.
    return [(offset, type, value),..]
    """
    if type(data) is str:
        buf = hex2bytes(data)
    else:
        buf = data

    if len(buf) % 32 != 0:
        buf += b"\x00" * (32 - (len(buf) % 32))

    results = []
    for i in range(len(buf) // 32):

        value = buf[i * 32 : (i + 1) * 32]
        uint256 = int.from_bytes(value, "big")

        if uint256 < len(buf) - 32 and uint256 > i * 32:
            offset = uint256
            length_bytes = buf[offset : offset + 32]
            length = int.from_bytes(length_bytes, "big")
            if offset + 32 + length <= len(buf):
                bytes_data = buf[offset + 32 : offset + 32 + length]
                if "\\" not in repr(bytes_data):  # Printable.
                    results.append(
                        (
                            "%#x" % (i * 32),
                            "string",
                            bytes_data.decode("utf-8")
                            + "\t"
                            + "// offset %#x length %d" % (offset, length),
                        )
                    )
                else:
                    results.append(
                        (
                            "%#x" % (i * 32),
                            "bytes",
                            str(bytes_data)
                            + "\t"
                            + "// offset %#x length %d" % (offset, length),
                        )
                    )

                continue  # This is an offset for bytes/string, just end processing. .

        if uint256 < 2**112:  # Small value as uint
            results.append(
                ("%#x" % (i * 32), "uint256", "%d (%#x)" % (uint256, uint256))
            )
        elif len("%x" % uint256) in range(29, 41):  # 12-18 Prefix zero as address.
            results.append(("%#x" % (i * 32), "address", "%0#42x" % uint256))
        else:
            results.append(("%#x" % (i * 32), "unknown", value.hex()))

    return results


def guess_single_calldata(data):
    results = guess_calldata_types(data)
    if len(results) == 1:
        return results[0][1], results[0][2]
    if len(results) == 3:
        if results[0][1] in ["bytes", "string"]:
            return results[0][1], results[0][2].split("// offset")[0]
    return "bytes", data


class CoinPrice(object):

    chain_coin_id = {
        "eth": "ethereum",
        "bsc": "binancecoin",
        "avax": "avalanche-2",
        "ftm": "fantom",
        "arbi": "ethereum",
        "op": "ethereum",
        "matic": "matic-network",
    }

    chain_id = {
        "eth": "ethereum",
        "bsc": "bsc",
        "arbi": "arbitrum",
        "avax": "avax",
        "ftm": "fantom",
        "op": "optimism",
        "matic": "polygon",
    }

    url = "https://coins.llama.fi/prices/current/"

    # https://coins.llama.fi/prices/current/coingecko:binancecoin
    # {"coins":{"coingecko:binancecoin":{"price":344.74,"symbol":"BNB","timestamp":1667551373,"confidence":0.99}}}

    @classmethod
    def get_native(cls, chain):
        gecko_id = "coingecko:%s" % cls.chain_coin_id.get(chain, chain)
        ret = requests.get(cls.url + gecko_id).json()["coins"]
        if gecko_id in ret:
            return ret[gecko_id]
        else:
            return None

    # https://coins.llama.fi/prices/current/ethereum:0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2,ethereum:0x419d0d8bdd9af5e606ae2232ed285aff190e711b
    # {"coins":{"ethereum:0x419d0d8bdd9af5e606ae2232ed285aff190e711b":{"decimals":8,"symbol":"FUN","price":0.00756368,"timestamp":1667555283,"confidence":0.99},"ethereum:0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2":{"decimals":18,"symbol":"WETH","price":1582.85,"timestamp":1667555277,"confidence":0.99}}}

    @classmethod
    def get_token(cls, chain, *addresses):
        chain = cls.chain_id.get(chain, chain)
        tokens = []
        for address in addresses:
            tokens.append("%s:%s" % (chain, address))
        url = cls.url + ",".join(tokens)
        ret = requests.get(url).json()["coins"]

        prices = []
        for token in tokens:
            if token in ret:
                info = ret[token]
                info["address"] = token.split(":")[1]
                prices.append(info)
            else:
                prices.append(None)
        return prices
