from typing import Optional


class OpCode(object):

    mnemonic_map = {}
    code_map = {}

    def __init__(
        self, mnemonic: str, code: int, inputs: int, outputs: int, gas: int
    ) -> None:
        self.mnemonic = mnemonic
        self.code = code
        self.inputs = inputs
        self.outputs = outputs
        self.gas = gas

    def __str__(self) -> str:
        return self.mnemonic

    @property
    def is_push(self) -> bool:
        return self.code >= 0x60 and self.code < 0x80

    @property
    def is_dup(self) -> bool:
        return self.code >= 0x80 and self.code < 0x90

    @property
    def is_swap(self) -> bool:
        return self.code >= 0x90 and self.code < 0xA0

    @property
    def is_jumpdest(self) -> bool:
        return self.code == 0x5B

    @property
    def is_log(self) -> bool:
        return self.code >= 0xA0 and self.code <= 0xA4

    @property
    def operand_size(self) -> int:
        if self.is_push:
            return self.code - 0x5F
        else:
            return 0

    @classmethod
    def from_mnemonic(cls, mnemonic: str) -> Optional["OpCode"]:
        return cls.mnemonic_map.get(mnemonic.upper(), OpCode.INVALID)

    @classmethod
    def from_code(cls, code: int) -> Optional["OpCode"]:
        assert code in cls.code_map, "Invalid opcode %s" % code
        return cls.code_map[code]

    @classmethod
    def init_opcode_set(cls) -> None:
        # Modified from: https://github.com/ethereum/pyethereum/blob/b704a5c6577863edc539a1ec3d2620a443b950fb/ethereum/opcodes.py
        # Ref: https://ethervm.io/
        # Ref: https://github1s.com/ethereum/py-evm/blob/HEAD/eth/vm/opcode_values.py

        opcodes = {
            #
            # Stop and Arithmetic
            #
            0x00: ["STOP", 0, 0, 0],
            0x01: ["ADD", 2, 1, 3],
            0x02: ["MUL", 2, 1, 5],
            0x03: ["SUB", 2, 1, 3],
            0x04: ["DIV", 2, 1, 5],
            0x05: ["SDIV", 2, 1, 5],
            0x06: ["MOD", 2, 1, 5],
            0x07: ["SMOD", 2, 1, 5],
            0x08: ["ADDMOD", 3, 1, 8],
            0x09: ["MULMOD", 3, 1, 8],
            0x0A: ["EXP", 2, 1, 10],  # >=10
            0x0B: ["SIGNEXTEND", 2, 1, 5],
            #
            # Comparison and Bitwise Logic
            #
            0x10: ["LT", 2, 1, 3],
            0x11: ["GT", 2, 1, 3],
            0x12: ["SLT", 2, 1, 3],
            0x13: ["SGT", 2, 1, 3],
            0x14: ["EQ", 2, 1, 3],
            0x15: ["ISZERO", 1, 1, 3],
            0x16: ["AND", 2, 1, 3],
            0x17: ["OR", 2, 1, 3],
            0x18: ["XOR", 2, 1, 3],
            0x19: ["NOT", 1, 1, 3],
            0x1A: ["BYTE", 2, 1, 3],
            0x1B: ["SHL", 2, 1, 3],
            0x1C: ["SHR", 2, 1, 3],
            0x1E: ["SAR", 2, 1, 3],
            #
            # Sha3
            #
            0x20: ["SHA3", 2, 1, 30],  # >=30
            #
            # Environment Information
            #
            0x30: ["ADDRESS", 0, 1, 2],
            0x31: ["BALANCE", 1, 1, 400],
            0x32: ["ORIGIN", 0, 1, 2],
            0x33: ["CALLER", 0, 1, 2],
            0x34: ["CALLVALUE", 0, 1, 2],
            0x35: ["CALLDATALOAD", 1, 1, 3],
            0x36: ["CALLDATASIZE", 0, 1, 2],
            0x37: ["CALLDATACOPY", 3, 0, 3],  # >=3
            0x38: ["CODESIZE", 0, 1, 2],
            0x39: ["CODECOPY", 3, 0, 3],  # >=3
            0x3A: ["GASPRICE", 0, 1, 2],
            0x3B: ["EXTCODESIZE", 1, 1, 700],
            0x3C: ["EXTCODECOPY", 4, 0, 700],
            0x3D: ["RETURNDATASIZE", 0, 1, 2],
            0x3E: ["RETURNDATACOPY", 3, 0, 3],
            0x3F: ["EXTCODEHASH", 1, 1, 30],
            #
            # Block Information
            #
            0x40: ["BLOCKHASH", 1, 1, 20],
            0x41: ["COINBASE", 0, 1, 2],
            0x42: ["TIMESTAMP", 0, 1, 2],
            0x43: ["NUMBER", 0, 1, 2],
            0x44: ["DIFFICULTY", 0, 1, 2],
            0x45: ["GASLIMIT", 0, 1, 2],
            # These opcodes seem to belong in the environment block,
            # but we are out of opcode space in 0x3*
            0x46: ["CHAINID", 0, 1, 2],
            0x47: ["SELFBALANCE", 0, 1, 2],
            0x48: ["BASEFEE", 0, 1, 2],
            #
            # Stack, Memory, Storage and Flow Operations
            #
            0x50: ["POP", 1, 0, 2],
            0x51: ["MLOAD", 1, 1, 3],
            0x52: ["MSTORE", 2, 0, 3],
            0x53: ["MSTORE8", 2, 0, 3],
            0x54: [
                "SLOAD",
                1,
                1,
                200,
            ],  # actual cost 5000-20000 depending on circumstance
            0x55: ["SSTORE", 2, 0, 0],
            0x56: ["JUMP", 1, 0, 8],
            0x57: ["JUMPI", 2, 0, 10],
            0x58: ["PC", 0, 1, 2],
            0x59: ["MSIZE", 0, 1, 2],
            0x5A: ["GAS", 0, 1, 2],
            0x5B: ["JUMPDEST", 0, 0, 1],
            #
            # Logging
            #
            0xA0: ["LOG0", 2, 0, 375],
            0xA1: ["LOG1", 3, 0, 750],
            0xA2: ["LOG2", 4, 0, 1125],
            0xA3: ["LOG3", 5, 0, 1500],
            0xA4: ["LOG4", 6, 0, 1875],
            #
            # System
            #
            0xF0: ["CREATE", 3, 1, 32000],
            0xF1: ["CALL", 7, 1, 700],
            0xF2: ["CALLCODE", 7, 1, 700],
            0xF3: ["RETURN", 2, 0, 0],
            0xF4: ["DELEGATECALL", 6, 1, 700],
            0xF5: ["CREATE2", 4, 1, 32000],
            0xFA: ["STATICCALL", 6, 1, 40],
            0xFD: ["REVERT", 2, 0, 0],
            0xFE: ["INVALID", 0, 0, 0],
            0xFF: ["SELFDESTRUCT", 1, 0, 5000],
        }

        for i in range(1, 33):
            opcodes[0x5F + i] = ["PUSH" + str(i), 0, 1, 3]

        for i in range(1, 17):
            opcodes[0x7F + i] = ["DUP" + str(i), i, i + 1, 3]
            opcodes[0x8F + i] = ["SWAP" + str(i), i + 1, i + 1, 3]

        for code in range(0, 0x100):
            if code in opcodes:
                mnemonic, inputs, outputs, gas = opcodes[code]
                op = cls(mnemonic, code, inputs, outputs, gas)

                cls.mnemonic_map[mnemonic] = op
                cls.code_map[code] = op
                setattr(cls, mnemonic, op)
            else:
                # Set all other slots as INVALID.
                op = cls("INVALID", code, 0, 0, 0)
                cls.code_map[code] = op


OpCode.init_opcode_set()
