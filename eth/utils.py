import json
import os
import atexit

import requests
from web3 import Web3

from core.config import SIG_DB_PATH, SIG_DB_URL
from core.log import logger

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

class SelectorDatabase(object):

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
        
    def get_sig(self, sig, only_one=False):
        if type(sig) is int:
            sig = '%08x' % sig
        else:
            sig = str(sig).lower()
            if sig.startswith('0x'):
                sig = sig[2:]
        
        # No 0x prefix
        if sig in self.db:
            sigs = self.db[sig]
            if type(sigs) is str:
                sigs = [sigs]
        else:
            sigs = self.get_sig_online(sig, False)
            if sigs:
                self.db[sig] = sigs
        
        assert type(sigs) is list, "get_sig: should always be list here."
        if only_one:
            if sigs:
                return sigs[0]
            else:
                return None
        else:
            return sigs
            

    def get_sig_online(self, sig, only_one=False):
        try:
            if type(sig) is int:
                sig = hex(sig)
            if not sig.startswith('0x'):
                sig = "0x" + sig

            url = 'https://www.4byte.directory/api/v1/signatures/?hex_signature=%s' % sig
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

sig_db = SelectorDatabase()

def get_4byte_sig(sig, only_one=False):
    return sig_db.get_sig(sig, only_one)

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