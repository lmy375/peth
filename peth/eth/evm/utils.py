import rlp
from web3 import Web3

from ..utils import keccak256

UINT_256_MAX = 2**256 - 1
UINT_256_CEILING = 2**256
UINT_255_MAX = 2**255 - 1
UINT_255_CEILING = 2**255
UINT_160_MAX = 2**160 - 1

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
USER_1_ADDRESS = "0x1000000000000000000000000000000000000000"
USER_2_ADDRESS = "0x2000000000000000000000000000000000000000"


def to_lower_address(s: str):
    a = str(s).lower()
    assert Web3.is_address(a), f"{s} not a valid address"
    return a


def address_to_bytes(addr: str):
    return Web3.to_bytes(hexstr=addr)


def address_to_uint(addr: str):
    return Web3.to_int(address_to_bytes(addr))


def to_int256(x: int) -> int:
    if x < UINT_255_CEILING:
        return x
    else:
        return x - UINT_256_CEILING


def to_uint256(x: int) -> int:
    return x & UINT_256_MAX


def data_to_uint(data: bytes) -> int:
    if len(data) < 32:
        data = bytearray(data)
        data.extend(b"\x00" * (32 - len(data)))
    return int.from_bytes(data, "big")


def uint_to_data(i: int, size: int = 32) -> bytes:
    return int.to_bytes(i, size, "big")


def uint_to_address(i: int) -> int:
    return Web3.to_checksum_address(int.to_bytes(i, 20, "big")).lower()


def generate_contract_address(address: str, nonce: int):
    return uint_to_address(
        int.from_bytes(
            keccak256(rlp.encode([address_to_bytes(address), nonce]))[12:], "big"
        )
    )


def generate_safe_contract_address(address: str, salt: int, call_data: bytes):
    return uint_to_address(
        int.from_bytes(
            keccak256(
                b"\xff"
                + address_to_bytes(address)
                + uint_to_data(salt)
                + keccak256(call_data)
            )[12:],
            "big",
        )
    )
