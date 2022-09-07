from peth.core.peth import Peth


def test_analyze_bytecode():
    peth = Peth.get_or_create('avax')
    selectors, addresses = peth.analyze_bytecode('0xB9257597EDdfA0eCaff04FF216939FBc31AAC026')
    assert len(selectors) == 5
    assert addresses[0] == '0xaD1ecb393F084403ACCA9dA6f71d4477745AF85E'