import codecs
from typing import Dict, List, Optional

from .opcodes import OpCode

class Instruction(object):
    def __init__(self, op: OpCode, opnd: Optional[int] = None, pc: int = 0) -> None:
        self.pc = pc
        self.op = op
        self.opnd = opnd

    def disasm(self) -> str:
        if self.op.operand_size == 0:
            return self.op.mnemonic
        else:
            return self.op.mnemonic + " " + hex(self.opnd)

    def asm(self) -> bytes:
        opnd_size = self.op.operand_size
        if opnd_size == 0:
            return self.op.code.to_bytes(1, "big")
        else:
            return self.op.code.to_bytes(1, "big") + self.opnd.to_bytes(
                opnd_size, "big"
            )

    def __repr__(self) -> str:
        return "%s %s %s" % (self.pc, self.asm().hex(), self.disasm())

    @property
    def instruction_size(self) -> int:
        return 1 + self.op.operand_size


class Code(object):
    def __init__(self, code) -> None:
        self.set_code(code)
        self.pc = 0
        self._instructions_cache: Dict[int, Instruction] = {}
        self.instructions: List[Instruction] = []

    def set_code(self, code):
        if type(code) is str and code.startswith("0x"):
            self.code = bytearray(codecs.decode(bytearray(code[2:], "ascii"), "hex"))
        elif type(code) is Code:
            self.code = bytearray(code.code)
        else:
            self.code = bytearray(code)

    def get_op(self) -> Optional[OpCode]:
        if self.pc >= len(self.code):
            return None
        op = OpCode.from_code(self.code[self.pc])
        return op

    def patch_bytes(self, offset, data):
        size = len(data)
        self.code[offset : offset + size] = data
        for pc in range(offset, offset + size):
            if pc in self._instructions_cache:
                self._instructions_cache.pop(pc)

    def patch_asm(self, offset, asm):
        data = Code.asm(asm)
        self.patch_bytes(offset, data)

    def next_instruction(self) -> Optional[Instruction]:
        ins = self._instructions_cache.get(self.pc, None)
        if ins:
            self.pc += ins.instruction_size
            return ins

        op = self.get_op()
        if op is None:
            return None

        ins_pc = self.pc
        self.pc += 1
        size = op.operand_size
        opnd = int.from_bytes(self.code[self.pc : self.pc + size], "big")
        self.pc += size
        ins = Instruction(op, opnd, ins_pc)
        self._instructions_cache[ins_pc] = ins
        return ins

    def get_instructions(self, force=True):
        if self.instructions and not force:
            return self.instructions

        while True:
            ins = self.next_instruction()
            if ins is None:
                break
            self.instructions.append(ins)
        return self.instructions

    @property
    def size(self):
        return len(self.code)

    @classmethod
    def from_asm(self, asm: str):
        lines = asm.strip().splitlines()
        code = b""
        for line in lines:
            ops = line.split()
            op = OpCode.from_mnemonic(ops[0])
            if op.operand_size:
                opnd = ops[1]
                if opnd.startswith("0x"):
                    opnd = int(opnd, 16)
                else:
                    opnd = int(opnd)
                ins = Instruction(op, opnd)
            else:
                ins = Instruction(op)
            code += ins.asm()
        return Code(code)

    @staticmethod
    def asm(asm: str) -> bytes:
        return Code.from_asm(asm).code

    @staticmethod
    def disasm(code: bytes) -> str:
        asm = ""
        for ins in Code(code).get_instructions():
            asm += ins.disasm() + "\n"
        return asm
