import json
import os
import atexit
import re
from typing import Any, Dict
from pytest import skip

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
                logger.info("Downloading SelectorDatabase from %s ..." % SIG_DB_URL)
                r = requests.get(SIG_DB_URL)
                self.db = r.json()
                logger.info("OK")
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

            # Get sig from sam's db.

            # https://sig.eth.samczsun.com/api/v1/signatures\?function\=0xa9059cbb
            # {"ok":true,"result":{"event":{},"function":{"0xa9059cbb":[{"name":"transfer(address,uint256)","filtered":false}]}}}

            if not selector.startswith('0x'):
                selector = '0x' + selector
            
            url = 'https://sig.eth.samczsun.com/api/v1/signatures?function=%s' % selector
            res = requests.get(url).json()
            results = res["result"]["function"][selector]
            
            if only_one:
                if results:
                    return results[0]['name']
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

def convert_value(value):
    """
    Guess value type and convert.
    """
    STR_PATTERN = '^[\'"](.*)[\'"]$'
    DEC_PATTERN = '^\d+$'
    HEX_PATTERN = '^[0-9A-Fa-fXx]+$'
    
    if Web3.isAddress(value): # address
        return value
    elif re.match(STR_PATTERN, value): # string.
        return re.findall(STR_PATTERN, value)[0]
    elif re.match(DEC_PATTERN, value): # decimal
        return int(value)
    elif re.match(HEX_PATTERN, value): # hexcimal
        return int(value, 16)
    else:
        raise NotImplementedError("Can not convert value: %s" % value)

def guess_calldata_types(data):
    """
    data: hex data without selector.
    return [(type, value),..]
    """
    buf = hex2bytes(data)
    if len(buf) % 32 != 0:
        buf += b"\x00" * (32 - (len(buf) % 32))
    
    results = []
    for i in range(len(buf)//32):

        value = buf[i*32: (i+1)*32]
        uint256 = int.from_bytes(value, 'big')

        if uint256 < len(buf) - 32 and uint256 > i * 32:
            offset = uint256
            length_bytes = buf[offset: offset + 32]
            length = int.from_bytes(length_bytes, 'big')
            if offset + 32 + length <= len(buf):
                bytes_data = buf[offset + 32: offset + 32 + length]
                if '\\' not in repr(bytes_data): # Printable.
                    results.append((
                        "%#x" % (i*32), 
                        "string",
                        bytes_data.decode('utf-8') + '\t' + "// offset %#x length %d" % (offset, length)
                    ))
                else:
                    results.append((
                        "%#x" % (i*32), 
                        "bytes",  
                        str(bytes_data) + '\t' + "// offset %#x length %d" % (offset, length)
                    ))

                continue # This is an offset for bytes/string, just end processing. .

        if uint256 < 2**112: # Small value as uint
            results.append(("%#x" % (i*32), "uint256", "%d (%#x)" %(uint256, uint256)))
        elif len('%x' % uint256) in range(29, 41): # 12-18 Prefix zero as address.
            results.append(("%#x" % (i*32), "address", '%0#42x' % uint256))
        else:
            results.append(("%#x" % (i*32), "unknown", value.hex()))

    return results
