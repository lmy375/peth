import pytest

from peth.eth.abi import ABIFunction
from peth.eth.bytecode import Code
from peth.eth.evm.utils import address_to_uint, uint_to_address
from peth.eth.evm.vm import VM

from .evm_test_codes import erc20_deploycode, erc20_runtimecode


@pytest.fixture
def vm():
    return VM()


def test_basic_add(vm: VM):
    code = Code.from_asm(
        """
        push1 1
        push1 2
        add
        """
    )
    r = vm.execute(code)
    assert r.stack_top == 3


def test_add_overflow(vm: VM):
    code = Code.from_asm(
        f"""
        push32 {hex(2**256-1)}
        push1 1
        add
        """
    )
    r = vm.execute(code)
    assert r.stack_top == 0


def test_tx_code(vm: VM):
    vm.transaction.to = uint_to_address(0x1111)
    vm.transaction.sender = uint_to_address(0x2222)
    vm.transaction.origin = uint_to_address(0x3333)

    vm.transaction.value = 1000
    vm.chain.set_balance(vm.transaction.sender, 1000)

    code = Code.from_asm(
        """
        address
        caller
        caller
        balance
        origin
        callvalue
        """
    )
    r = vm.execute(code)
    assert r.stack[0] == address_to_uint(vm.transaction.to)
    assert r.stack[1] == address_to_uint(vm.transaction.sender)
    assert r.stack[2] == 1000
    assert r.stack[3] == address_to_uint(vm.transaction.origin)
    assert r.stack[4] == vm.transaction.value
    assert len(r.stack) == 5


def test_chain_code(vm: VM):
    vm.chain.coinbase = uint_to_address(0x1111)
    vm.chain.timestamp = 2222
    vm.chain.blocknumber = 3333
    vm.chain.difficulty = 4444
    vm.chain.gaslimit = 5555
    vm.chain.basefee = 6666
    vm.chain.chainid = 7777
    code = Code.from_asm(
        """
        coinbase
        timestamp
        number
        difficulty
        gaslimit
        basefee
        chainid
        """
    )
    r = vm.execute(code)
    assert r.stack[0] == address_to_uint(vm.chain.coinbase)
    assert r.stack[1] == vm.chain.timestamp
    assert r.stack[2] == vm.chain.blocknumber
    assert r.stack[3] == vm.chain.difficulty
    assert r.stack[4] == vm.chain.gaslimit
    assert r.stack[5] == vm.chain.basefee
    assert r.stack[6] == vm.chain.chainid
    assert len(r.stack) == 7


def test_erc20(vm: VM):
    vm.transaction.sender = uint_to_address(0x1111)
    vm.transaction.to = uint_to_address(0x2222)

    # Executing deploy code should return runtime code.
    r = vm.execute(erc20_deploycode)
    assert r.returndata == Code(erc20_runtimecode).code

    contract = vm.chain.get_account(vm.transaction.to)
    assert contract
    assert contract.storage != {}

    # Executing runtime code without input should revert.
    r = vm.execute(erc20_runtimecode)
    assert r.reverted

    fn = ABIFunction("balanceOf(address)->(uint256)")
    input = fn.encode_input([vm.transaction.sender])
    r = vm.execute(erc20_runtimecode, input)
    assert fn.decode_output(r.returndata) == 0x10000000


def test_destruct(vm: VM):
    vm.transaction.sender = uint_to_address(0x1111)
    vm.transaction.to = uint_to_address(0x2222)
    vm.chain.set_balance(vm.transaction.to, 100)

    code = Code.from_asm(
        """
        push32 0x1111
        selfdestruct
        """
    )
    vm.chain.set_code(vm.transaction.to, code.code)
    r = vm.execute(code)
    assert r.success
    assert vm.chain.get_balance(vm.transaction.sender) == 100
