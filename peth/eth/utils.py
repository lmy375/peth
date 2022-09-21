import json
import os
import atexit
from typing import Any, Dict

import requests
from web3 import Web3

from peth.core.config import SIG_DB_PATH, SIG_DB_URL
from peth.core.log import logger

ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

try:
    from Crypto.Hash import keccak

    def sha3_256(x):
        return keccak.new(digest_bits=256, data=x).digest()

except ImportError:
    import sha3 as _sha3

    def sha3_256(x):
        return _sha3.keccak_256(x).digest()

def func_selector(func_sig: str):
    return sha3_256(bytes(func_sig, "ascii", "ignore"))[:4]

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

        if not os.path.exists(SIG_DB_PATH):
            try:
                r = requests.get(SIG_DB_URL)
                self.db = r.json()
            except Exception as e:
                logger.warn("SelectorDatabase init failed. %s" % e)
            logger.debug("Load sig db from %s" % SIG_DB_URL)
        else:
            self.db = json.load(open(SIG_DB_PATH))
            logger.debug("Load sig db from %s" % SIG_DB_PATH)

        atexit.register(self.save)
        
    def get_sig_from_selector(self, selector, only_one=False, online=True):
        if type(selector) is int:
            selector = '%08x' % selector
        else:
            selector = str(selector).lower()
            if selector.startswith('0x'):
                selector = selector[2:]
        
        # No 0x prefix
        if selector in self.db:
            sigs = self.db[selector]
            if type(sigs) is str:
                sigs = [sigs]
        elif online:
            sigs = self.get_sig_online(selector, False)
            if sigs:
                self.db[selector] = sigs
        else:
            sigs = [] # Off-line empty result.
        
        assert type(sigs) is list, "get_sig: should always be list here."
        if only_one:
            if sigs:
                return sigs[0]
            else:
                return None
        else:
            return sigs

    def get_sig_from_text(self, text):
        ret = [] # (selector, [sigs])
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
            if type(selector) is int:
                selector = '%08x' % selector
            else:
                selector = str(selector).lower()
            if selector.startswith('0x'):
                selector = selector[2:]

            url = 'https://www.4byte.directory/api/v1/signatures/?hex_signature=%s' % selector
            r = requests.get(url)
            results = r.json()["results"]
            
            if only_one:
                if results:
                    return results[0]["text_signature"]
                else:
                    return None
            else:
                return [i["text_signature"] for i in results]
        
        except Exception:
            if only_one:
                return None
            else:
                return []  
        
    def save(self):
        json.dump(self.db, open(SIG_DB_PATH, "w"))
        logger.debug("Save sig db to %s" % SIG_DB_PATH)


    @classmethod
    def get(cls):
        if SelectorDatabase.single_instance is None:
            # This can be a little slow as it downloads data from github.
            SelectorDatabase.single_instance = SelectorDatabase()
        return SelectorDatabase.single_instance


def selector_to_sigs(selector, only_one=False):
    db = SelectorDatabase.get()
    return db.get_sig_from_selector(selector, only_one)


def process_args(args):
    """
    Try to covert address, int values.
    """
    r = []
    for arg in args:
        if Web3.isAddress(arg):
            r.append(Web3.toChecksumAddress(arg))
            continue
            
        try:
            if arg.startswith('0x'):
                r.append(int(arg, 16))
            else:
                r.append(int(arg))
        except Exception as e:
            r.append(arg)
    return r
    
def hex2bytes(hex_data):
    if hex_data.startswith('0x'):
        hex_data = hex_data[2:]
    return bytes.fromhex(hex_data)