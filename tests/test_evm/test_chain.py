import pytest

from peth.eth.evm.chain import Chain
from peth.eth.evm.contract import Contract
from peth.eth.evm.utils import uint_to_address

from .evm_test_codes import erc20_deploycode, internal_tx_deploycode


@pytest.fixture
def chain():
    return Chain()


a1 = uint_to_address(0x1001)
a2 = uint_to_address(0x1002)


def test_balance(chain: Chain):
    assert chain.get_balance(a1) == 0

    chain.set_balance(a1, 1000)
    assert chain.get_balance(a1) == 1000

    r = chain._transfer_balance(a1, a2, 100)
    assert r.success
    assert chain.get_balance(a1) == 900
    assert chain.get_balance(a2) == 100


def test_storage(chain: Chain):
    chain.set_storage(a1, 1, 0x1234)
    assert chain.get_storage(a1, 1) == 0x1234


def test_snapshot(chain: Chain):
    chain.blocknumber = 1
    chain.snapshot()

    chain.blocknumber += 1
    chain.set_balance(a1, 1000)
    chain.set_storage(a2, 1234, 1234)
    chain.snapshot()

    chain.blocknumber += 1
    chain.set_storage(a2, 1234, 5678)
    chain.set_balance(a2, 1000)
    chain.set_balance(a1, 2000)

    chain.revert()
    assert chain.blocknumber == 2
    assert chain.get_balance(a2) == 0
    assert chain.get_balance(a1) == 1000
    assert chain.get_storage(a2, 1234) == 1234

    chain.revert()
    assert chain.blocknumber == 1
    assert chain.get_balance(a1) == 0
    assert chain.get_storage(a2, 1234) == 0


def test_erc20(chain: Chain):
    contract = Contract(sender=a1, deploycode=erc20_deploycode, chain=chain)
    assert contract.address

    assert contract.call("name() -> (string)") == "MyToken"
    assert contract.call("balanceOf(address) -> (uint)", a1) == 0x10000000

    contract.call("transfer(address, uint256)", a2, 0x1234)

    assert contract.call("balanceOf(address) -> (uint)", a1) == 0x10000000 - 0x1234
    assert contract.call("balanceOf(address) -> (uint)", a2) == 0x1234


def test_internal_tx(chain: Chain):
    # Should fail.
    main = Contract(sender=a1, deploycode=internal_tx_deploycode, chain=chain)
    assert main.address is None

    chain.set_balance(a1, 20000)
    main = Contract(
        sender=a1, deploycode=internal_tx_deploycode, value=20000, chain=chain
    )
    assert main.address

    sub_address = main.call("target()->(address)")
    assert sub_address

    sub = Contract(sub_address, sender=main.address, chain=chain)
    assert sub.call("target()->(address)") == main.address

    assert chain.get_balance(main.address) == 10000
    assert chain.get_balance(sub.address) == 10000

    main.call("test1()")
    assert chain.get_balance(main.address) == 9400
    assert chain.get_balance(sub.address) == 10600

    main.call("test2()")
    assert chain.get_balance(main.address) == 9100
    assert chain.get_balance(sub.address) == 10900

    r = main.send("test3()")
    assert not r.success
    assert chain.get_balance(main.address) == 9100
    assert chain.get_balance(sub.address) == 10900

    main.call("test4()")
    assert chain.get_balance(main.address) == 9100
    assert chain.get_balance(sub.address) == 10900

    r = main.send("test5()")
    assert not r.success
    assert chain.get_balance(main.address) == 9100
    assert chain.get_balance(sub.address) == 10900

    main.call("test6()")
    assert chain.get_balance(main.address) == 8800
    assert chain.get_balance(sub.address) == 11200

    main.call("test7()")
    assert chain.get_balance(main.address) == 8200
    assert chain.get_balance(sub.address) == 11800

    main.call("test8()")
    assert chain.get_balance(main.address) == 7900
    assert chain.get_balance(sub.address) == 12100

    r = main.send("test9()")
    assert not r.success
    assert chain.get_balance(main.address) == 7900
    assert chain.get_balance(sub.address) == 12100

    r = main.send("test10()")
    assert not r.success
    assert chain.get_balance(main.address) == 7900
    assert chain.get_balance(sub.address) == 12100

    main.call("test11()")
    assert chain.get_balance(main.address) == 7300
    assert chain.get_balance(sub.address) == 12700

    r = main.send("test12()")
    assert not r.success
    assert chain.get_balance(main.address) == 7300
    assert chain.get_balance(sub.address) == 12700

    main.call("test13()")
    assert chain.get_balance(main.address) == 7200
    assert chain.get_balance(sub.address) == 12800
