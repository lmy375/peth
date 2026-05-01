import functools
from typing import List, Union

from ..bytecode import Code
from ..opcodes import OpCode
from .exceptions import InvalidHandlerError, InvalidJumpDestination, VMExecutionError
from .receipt import Receipt
from .transaction import Transaction
from .utils import (
    UINT_256_MAX,
    address_to_uint,
    data_to_uint,
    keccak256,
    to_int256,
    to_uint256,
    uint_to_address,
    uint_to_data,
)


class VM:

    debug = False
    trace = False

    # Class-level handler template: maps opcode -> (handler_name, partial_arg)
    # Built once and shared across all VM instances for performance.
    _handler_template = None

    def __init__(self, chain=None, tx: Transaction = None) -> None:
        if chain:
            self.chain = chain
        else:
            # Import here to avoid import-circle.
            from .chain import Chain

            self.chain = Chain()

        self.code = None
        if tx:
            self.transaction = tx
            if tx.to == 0 and tx.data:
                self.code = Code(tx.data)
        else:
            self.transaction = Transaction()

        self._current_ins = None
        self.result = Receipt()

        self._init_handlers()

    @classmethod
    def _build_handler_template(cls):
        """Build handler template once at class level."""
        if cls._handler_template is not None:
            return
        template = [None] * 256  # None means _invalid
        for mnemonic, op in OpCode.mnemonic_map.items():
            code = op.code
            if op.is_push:
                template[code] = ("_push", code - 0x5F)
            elif op.is_dup:
                template[code] = ("_dup", code - 0x7F)
            elif op.is_swap:
                template[code] = ("_swap", code - 0x8F)
            elif op.is_log:
                template[code] = ("_log", code - 0xA0)
            else:
                template[code] = ("_" + mnemonic.lower(), None)
        cls._handler_template = template

    def _init_handlers(self) -> None:
        VM._build_handler_template()
        self._handlers = [self._invalid] * 256
        for code, entry in enumerate(VM._handler_template):
            if entry is None:
                continue
            method_name, partial_arg = entry
            method = getattr(self, method_name, self._invalid)
            if partial_arg is not None:
                self._handlers[code] = functools.partial(method, partial_arg)
            else:
                self._handlers[code] = method

    def _trace(self, msg: str):
        if self.trace or self.debug:
            self.result.trace.post_trace(self._current_ins.pc, msg)

            if self.debug:
                print(self.result.trace.current_step)

    def reset(self):
        self._current_ins = None
        self.code.pc = 0
        self.transaction.gas = 100000

        # Each time we run, use a new stack/memory.
        self.result = Receipt()
        self._stack = self.result.stack
        self._memory = self.result.memory

    def _read_memory(self, offset: int, size: int) -> bytearray:
        # Memory allocation.
        if offset + size > len(self._memory):
            self._memory.extend(b"\x00" * (offset + size - len(self._memory)))
        data = self._memory[offset : offset + size]
        if len(data) != size:
            raise RuntimeError(
                f"Memory read size mismatch: expected {size}, got {len(data)}"
            )
        return data

    def _write_memory(
        self, offset: int, size: int, data: Union[bytearray, bytes]
    ) -> None:
        if len(data) != size:
            raise ValueError("Wrong data size.")
        if offset + size > len(self._memory):
            self._memory.extend(b"\x00" * (offset + size - len(self._memory)))
        self._memory[offset : offset + size] = data

    def _stack_push(self, value: int) -> None:
        self._stack.append(value)

    def _stack_pop(self) -> int:
        return self._stack.pop()

    def _stack_pop_values(self, n: int) -> List[int]:
        return [self._stack.pop() for _ in range(n)]

    def execute(self, code=None, input_data=None, reset=True) -> Receipt:
        if code:
            self.code = Code(code)

        if input_data:
            self.transaction.data = input_data

        if not self.code:
            raise VMExecutionError("EVM: No code set.")

        if reset:
            self.reset()

        self._running = True
        while self._running:
            self.transaction.gas -= 1
            if self.transaction.gas <= 0:
                self.result.error = VMExecutionError("Out of gas")
                break

            ins = self.code.next_instruction()
            self._current_ins = ins

            if ins is None:  # end.
                break

            if self.trace or self.debug:
                self.result.trace.pre_trace(
                    ins.pc,
                    ins.op.mnemonic,
                    self.transaction.depth,
                    list(self._stack),  # copy stack.
                )
            try:

                self._handlers[ins.op.code]()
            except VMExecutionError as e:
                self.result.error = e
                break

        self._running = False
        return self.result

    ##########################
    #  EVM Logic.
    ##########################

    #
    # Stop and Arithmetic
    #

    def _stop(self):
        self._running = False
        self._trace("stop")

    def _add(self):
        r1, r2 = self._stack_pop_values(2)
        v = to_uint256(r1 + r2)
        self._stack_push(v)
        self._trace("%#x + %#x => %#x" % (r1, r2, v))

    def _mul(self):
        r1, r2 = self._stack_pop_values(2)
        v = to_uint256(r1 * r2)
        self._stack_push(v)
        self._trace("%#x * %#x => %#x" % (r1, r2, v))

    def _sub(self):
        r1, r2 = self._stack_pop_values(2)
        v = to_uint256(r1 - r2)
        self._stack_push(v)
        self._trace("%#x - %#x => %#x" % (r1, r2, v))

    def _div(self):
        r1, r2 = self._stack_pop_values(2)
        v = 0 if r2 == 0 else r1 // r2  # should never overflow here.
        self._stack_push(v)
        self._trace("%#x / %#x => %#x" % (r1, r2, v))

    def _mod(self):
        r1, r2 = self._stack_pop_values(2)
        v = 0 if r2 == 0 else r1 % r2  # should never overflow here.
        self._stack_push(v)
        self._trace("%#x %% %#x => %#x" % (r1, r2, v))

    def _sdiv(self):
        r1, r2 = self._stack_pop_values(2)
        s1 = to_int256(r1)
        s2 = to_int256(r2)
        v = (
            0
            if s2 == 0
            else to_uint256(abs(s1) // abs(s2) * (-1 if s1 * s2 < 0 else 1))
        )
        self._stack_push(v)
        self._trace(f"{s1} / {s2} => {v}")

    def _smod(self):
        r1, r2 = self._stack_pop_values(2)
        s1 = to_int256(r1)
        s2 = to_int256(r2)
        v = 0 if s2 == 0 else to_uint256(abs(s1) % abs(s2) * (-1 if s1 < 0 else 1))
        self._stack_push(v)
        self._trace(f"{s1} % {s2} => {v}")

    def _addmod(self):
        r1, r2, r3 = self._stack_pop_values(3)
        v = (r1 + r2) % r3 if r3 else 0
        self._stack_push(v)
        self._trace("(%#x + %#x) %% %#x  => %#x" % (r1, r2, r3, v))

    def _mulmod(self):
        r1, r2, r3 = self._stack_pop_values(3)
        v = (r1 * r2) % r3 if r3 else 0
        self._stack_push(v)
        self._trace("(%#x * %#x) %% %#x  => %#x" % (r1, r2, r3, v))

    def _exp(self):
        r1, r2 = self._stack_pop_values(2)
        v = pow(r1, r2, UINT_256_MAX)
        self._stack_push(v)
        self._trace("%#x ** %#x => %#x" % (r1, r2, v))

    def _signextend(self):
        r1, r2 = self._stack_pop_values(2)

        v = r2
        if r1 <= 31:
            testbit = r1 * 8 + 7
            signbit = 1 << testbit
            if r2 & signbit:  # negative.  1 extend.
                v = r2 | (UINT_256_MAX - signbit)
            else:  # truncate.
                v = r2 & (signbit - 1)
        self._stack_push(v)
        self._trace(f"{hex(r2)} signextend {r1} => {hex(v)}")

    #
    # Comparison and Bitwise Logic
    #
    def _lt(self):
        r1, r2 = self._stack_pop_values(2)
        v = 1 if r1 < r2 else 0
        self._stack_push(v)
        self._trace("%#x < %#x => %s" % (r1, r2, v))

    def _gt(self):
        r1, r2 = self._stack_pop_values(2)
        v = 1 if r1 > r2 else 0
        self._stack_push(v)
        self._trace("%#x > %#x => %s" % (r1, r2, v))

    def _slt(self):
        r1, r2 = self._stack_pop_values(2)
        s1 = to_int256(r1)
        s2 = to_int256(r2)
        v = 1 if s1 < s2 else 0
        self._stack_push(v)
        self._trace(f"{s1} < {s2} => {v}")

    def _sgt(self):
        r1, r2 = self._stack_pop_values(2)
        s1 = to_int256(r1)
        s2 = to_int256(r2)
        v = 1 if s1 > s2 else 0
        self._stack_push(v)
        self._trace(f"{s1} > {s2} => {v}")

    def _eq(self):
        r1, r2 = self._stack_pop_values(2)
        v = 1 if r1 == r2 else 0
        self._stack_push(v)
        self._trace(f"{hex(r1)} == {hex(r2)} => {v}")

    def _iszero(self):
        r1 = self._stack_pop()
        v = 1 if r1 == 0 else 0
        self._stack_push(v)
        self._trace(f"{hex(r1)} == 0 => {v}")

    def _and(self):
        r1, r2 = self._stack_pop_values(2)
        v = r1 & r2
        self._stack_push(v)
        self._trace("%#x & %#x => %#x" % (r1, r2, v))

    def _or(self):
        r1, r2 = self._stack_pop_values(2)
        v = r1 | r2
        self._stack_push(v)
        self._trace("%#x | %#x => %#x" % (r1, r2, v))

    def _xor(self):
        r1, r2 = self._stack_pop_values(2)
        v = r1 ^ r2
        self._stack_push(v)
        self._trace("%#x ^ %#x => %#x" % (r1, r2, v))

    def _not(self):
        r1 = self._stack_pop()
        v = UINT_256_MAX - r1
        self._stack_push(v)
        self._trace("~ %#x => %#x" % (r1, v))

    def _byte(self):
        r1, r2 = self._stack_pop_values(2)
        v = 0 if r1 >= 32 else (r2 // pow(256, 31 - r1)) % 256
        self._stack_push(v)
        self._trace("%#x[%s] => %#x" % (r2, r1, v))

    def _shl(self):
        r1, r2 = self._stack_pop_values(2)
        if r1 >= 256:
            v = 0
        else:
            v = to_uint256(r2 << r1)
        self._stack_push(v)
        self._trace("%#x << %s => %#x" % (r2, r1, v))

    def _shr(self):
        r1, r2 = self._stack_pop_values(2)
        if r1 >= 256:
            v = 0
        else:
            v = to_uint256(r2 >> r1)
        self._stack_push(v)
        self._trace("%#x >> %s => %#x" % (r2, r1, v))

    def _sar(self):
        r1, r2 = self._stack_pop_values(2)
        r2 = to_int256(r2)
        if r1 >= 256:
            v = 0 if r2 >= 0 else UINT_256_MAX  # -1
        else:
            v = to_uint256(r2 >> r1)
        self._stack_push(v)
        self._trace("%s >> %s => %#x" % (r2, r1, v))

    #
    # Sha3
    #
    def _sha3(self):
        offset, size = self._stack_pop_values(2)
        data = self._read_memory(offset, size)
        hash = keccak256(data)
        v = data_to_uint(hash)
        self._stack_push(v)
        self._trace(f"{data.hex()} => {hash.hex()}")

    #
    # Environment Information
    #

    def _address(self):
        v = address_to_uint(self.transaction.to)
        self._stack_push(v)
        self._trace(f"address(this) => {uint_to_address(v)}")

    def _balance(self):
        r1 = self._stack_pop()
        addr = uint_to_address(r1)
        v = self.chain.get_balance(addr)
        self._stack_push(v)
        self._trace(f"{addr}.balance => {v}")

    def _origin(self):
        addr = self.transaction.origin
        v = address_to_uint(addr)
        self._stack_push(v)
        self._trace(f"tx.origin => {addr}")

    def _caller(self):
        addr = self.transaction.sender
        v = address_to_uint(addr)
        self._stack_push(v)
        self._trace(f"msg.sender => {addr}")

    def _callvalue(self):
        v = self.transaction.value
        self._stack_push(v)
        self._trace(f"msg.value => {v}")

    def _calldataload(self):
        r = self._stack_pop()
        data = bytearray(self.transaction.data[r : r + 32])
        # Zero-pad if reading past end of calldata (EVM spec).
        if len(data) < 32:
            data.extend(b"\x00" * (32 - len(data)))
        v = data_to_uint(data)
        self._stack_push(v)
        self._trace(f"calldata[{r}] => {hex(v)}")

    def _calldatasize(self):
        v = len(self.transaction.data)
        self._stack_push(v)
        self._trace(f"calldatasize => {v}")

    def _calldatacopy(self):
        mem_start, calldata_start, size = self._stack_pop_values(3)
        data = self.transaction.data[calldata_start : calldata_start + size]
        data = bytearray(data)
        data.extend(b"\x00" * (size - len(data)))
        self._write_memory(mem_start, size, data)
        self._trace(f"calldatacopy({calldata_start}, {size}) => {mem_start}")

    def _codesize(self):
        v = self.code.size
        self._stack_push(v)
        self._trace(f"codesize => {v}")

    def _codecopy(self):
        mem_start, code_start, size = self._stack_pop_values(3)
        data = self.code.code[code_start : code_start + size]
        data = bytearray(data)
        data.extend(b"\x00" * (size - len(data)))
        self._write_memory(mem_start, size, data)
        self._trace(f"codecopy({code_start}, {size}) => {mem_start}")

    def _gasprice(self):
        v = self.transaction.gasprice
        self._stack_push(v)
        self._trace(f"tx.gasprice => {v}")

    def _extcodesize(self):
        r0 = self._stack_pop()
        addr = uint_to_address(r0)
        v = len(self.chain.get_code(addr))
        self._stack_push(v)
        self._trace(f"{addr}.codesize => {v}")

    def _extcodecopy(self):
        r0, mem_start, code_start, size = self._stack_pop_values(4)
        address = uint_to_address(r0)
        code = self.chain.get_code(address)
        data = code[code_start : code_start + size]
        self._write_memory(mem_start, size, data)
        self._trace(f"extcodecopy({address}, {code_start}, {size}) => {mem_start}")

    def _returndatasize(self):
        v = len(self.transaction.returndata)
        self._stack_push(v)
        self._trace(f"returndatasize => {v}")

    def _returndatacopy(self):
        mem_start, data_start, size = self._stack_pop_values(3)
        data = self.transaction.returndata[data_start : data_start + size]
        data = bytearray(data)
        data.extend(b"\x00" * (size - len(data)))
        self._write_memory(mem_start, size, data)
        self._trace(f"calldatacopy({data_start}, {size}) => {mem_start}")

    def _extcodehash(self):
        v = self._stack_pop()
        addr = uint_to_address(v)
        code = self.chain.get_code(addr)
        if code:
            v = data_to_uint(keccak256(code))
        else:
            v = 0

        self._stack_push(v)
        self._trace(f"extcodehash({addr}) => {hex(v)}")

    #
    # Block Information
    #
    def _blockhash(self):
        r = self._stack_pop()
        v = self.chain.get_blockhash(r)
        self._stack_push(v)
        self._trace(f"blockhash({r}) => {hex(v)}")

    def _coinbase(self):
        addr = self.chain.coinbase
        v = address_to_uint(addr)
        self._stack_push(v)
        self._trace(f"block.coinbase => {addr}")

    def _timestamp(self):
        v = self.chain.timestamp
        self._stack_push(v)
        self._trace(f"block.timestamp => {hex(v)}")

    def _number(self):
        v = self.chain.blocknumber
        self._stack_push(v)
        self._trace(f"block.number => {hex(v)}")

    def _difficulty(self):
        v = self.chain.difficulty
        self._stack_push(v)
        self._trace(f"block.difficulty => {hex(v)}")

    def _gaslimit(self):
        v = self.chain.gaslimit
        self._stack_push(v)
        self._trace(f"block.gaslimit => {hex(v)}")

    def _chainid(self):
        v = self.chain.chainid
        self._stack_push(v)
        self._trace(f"block.chainid => {hex(v)}")

    def _selfbalance(self):
        v = self.chain.get_balance(self.transaction.to)
        self._stack_push(v)
        self._trace(f"this.balance => {hex(v)}")

    def _basefee(self):
        v = self.chain.basefee
        self._stack_push(v)
        self._trace(f"block.basefee => {hex(v)}")

    #
    # Stack, Memory, Storage and Flow Operations
    #
    def _pop(self):
        v = self._stack_pop()
        self._trace(f"pop => {hex(v)}")

    def _mload(self):
        offset = self._stack_pop()

        data = self._read_memory(offset, 32)
        v = data_to_uint(data)
        self._stack_push(v)
        self._trace(f"mload({offset}) => {hex(v)}")

    def _mstore(self):
        offset, v = self._stack_pop_values(2)
        self._write_memory(offset, 32, uint_to_data(v, 32))
        self._trace(f"mstore[{offset}] = {hex(v)}")

    def _mstore8(self):
        offset, v = self._stack_pop_values(2)
        v = v & 0xFF
        self._write_memory(offset, 1, uint_to_data(v, 1))
        self._trace(f"mstore8[{offset}] = {hex(v)}")

    def _sload(self):
        slot = self._stack_pop()
        address = self.transaction.to
        v = self.chain.get_storage(address, slot)
        self._stack_push(v)
        self._trace(f"[{hex(slot)}] => {hex(v)}")

    def _sstore(self):
        slot, v = self._stack_pop_values(2)
        address = self.transaction.to
        self.chain.set_storage(address, slot, v)
        self._trace(f"{address}[{slot}] = {hex(v)}")

    def _jump(self):
        target = self._stack_pop()
        self._trace(f"jump => {target}")
        self.code.pc = target
        op = self.code.get_op()
        if op is None or not op.is_jumpdest:
            op_info = f"{op} {hex(op.code)}" if op is not None else "None"
            raise InvalidJumpDestination(f"Invalid jumpdest({op_info}) at {target}")

    def _jumpi(self):
        target, flag = self._stack_pop_values(2)
        self._trace(f"jumpi {target} => {flag}")
        if flag:
            self.code.pc = target
            op = self.code.get_op()
            if op is None or not op.is_jumpdest:
                op_info = f"{op} {hex(op.code)}" if op is not None else "None"
                raise InvalidJumpDestination(f"Invalid jumpdest({op_info}) at {target}")

    def _pc(self):
        v = self.code.pc - 1
        v = max(0, v)
        self._stack_push(v)
        self._trace(f"pc => {v}")

    def _msize(self):
        v = len(self._memory)
        self._stack_push(v)
        self._trace(f"msize => {v}")

    def _gas(self):
        v = self.transaction.gas
        self._stack_push(v)
        self._trace(f"gasLeft() => {v}")

    def _jumpdest(self):
        self._trace(f"jumpdest {self.code.pc - 1}")

    #
    # Block Information
    #

    def _push(self, n):
        v = self._current_ins.opnd
        self._stack_push(v)
        self._trace(f"push{n} => {hex(v)}")

    def _dup(self, n):
        v = self._stack[-n]
        self._stack_push(v)
        self._trace(f"dup{n} => {hex(v)}")

    def _swap(self, n):
        v = self._stack[-n - 1]
        top = self._stack[-1]
        self._stack[-1] = v
        self._stack[-n - 1] = top
        self._trace(f"swap{n} {hex(top)}(old top) <=> {hex(v)}(new top)")

    #
    # Logging
    #

    def _log(self, n):
        offset, size = self._stack_pop_values(2)
        topics = self._stack_pop_values(n)
        data = self._read_memory(offset, size)

        self.result.event_logs.append((self.transaction.to, topics, data))

        topics = ",".join(hex(i) for i in topics)
        self._trace(f"log{n} {topics} {data.hex()}")

    #
    # System
    #
    def _create(self):
        value, offset, size = self._stack_pop_values(3)
        data = self._read_memory(offset, size)
        tx = self.transaction.create_internal_tx(OpCode.CREATE, value=value, data=data)
        r = self.chain.apply_transaction(tx)
        v = address_to_uint(r.created_contract)
        self._stack_push(v)
        self._trace(f"create {value}, {offset}, {size} => {r.created_contract}")

    def _create2(self):
        value, offset, size, salt = self._stack_pop_values(4)
        data = self._read_memory(offset, size)
        tx = self.transaction.create_internal_tx(OpCode.CREATE2, value=value, data=data)
        tx.salt = salt
        r = self.chain.apply_transaction(tx)
        v = address_to_uint(r.created_contract)
        self._stack_push(v)
        self._trace(
            f"create2 {value}, {offset}, {size}, {salt} => {r.created_contract}"
        )

    def _do_call(self):
        gas, to = self._stack_pop_values(2)
        to = uint_to_address(to)
        if self._current_ins.op in [OpCode.CALL, OpCode.CALLCODE]:
            value = self._stack_pop()
        else:
            value = 0
        args_offset, args_size, return_offset, return_size = self._stack_pop_values(4)

        data = self._read_memory(args_offset, args_size)
        tx = self.transaction.create_internal_tx(
            self._current_ins.op, to, value, data, gas
        )

        self._trace(f"{self._current_ins.op} {to} {value} Begin")

        # Internal tx, don't update nonce.
        r = self.chain.apply_transaction(tx, False)
        if r.success:
            v = 1
        else:
            v = 0

        ret_data = bytearray(r.returndata)
        if len(ret_data) > return_size:
            ret_data = ret_data[:return_size]
        else:
            ret_data.extend(b"\x00" * (return_size - len(ret_data)))

        self._write_memory(return_offset, return_size, ret_data)

        self.transaction.returndata = r.returndata
        # Note: do NOT use trucated data here, or returndatasize will return wrong value.

        self._stack_push(v)
        self._trace(f"{self._current_ins.op} {to} {value} => {v}")

        # Collect sub execution trace to current trace.
        self.result.trace.add_sub_trace(r.trace)

    def _call(self):
        self._do_call()

    def _callcode(self):
        self._do_call()

    def _delegatecall(self):
        self._do_call()

    def _staticcall(self):
        self._do_call()

    def _return(self):
        offset, size = self._stack_pop_values(2)
        self.result.returndata = self._read_memory(offset, size)
        self._running = False
        self._trace(f"return {offset}, {size}, data:{self.result.returndata.hex()}")

    def _revert(self):
        offset, size = self._stack_pop_values(2)
        self.result.returndata = self._read_memory(offset, size)
        self.result.reverted = True
        self._running = False
        self._trace(f"revert {offset}, {size}, data:{self.result.returndata.hex()}")

    def _selfdestruct(self):
        beneficiary = self._stack_pop()
        beneficiary = uint_to_address(beneficiary)
        self.chain.destruct_contract(self.transaction.code_address, beneficiary)
        self._trace(f"selfdestruct {self.transaction.code_address} -> {beneficiary}")
        self._running = False

    def _invalid(self):
        raise InvalidHandlerError(
            "Invalid opcode handler called. %s" % self._current_ins
        )
