from string import hexdigits
import requests
from web3 import Web3

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

def get_4byte_sig(sig, only_one=False):
    try:
        if type(sig) is int:
            sig = hex(sig)
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