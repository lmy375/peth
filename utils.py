import requests

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