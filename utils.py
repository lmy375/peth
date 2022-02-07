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
