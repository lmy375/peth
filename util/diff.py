import os

from core.peth import Peth
from eth.scan import ScanAPI

from .source import ContractSource

def diff_source(src1, src2, output=None):
    src1 = ContractSource(src1)
    src2 = ContractSource(src2)
    if output:
        output = os.path.join('diff', output)
    src1.compare(src2, output)

def diff_chain_src(chain1, addr1, chain2, addr2, output=None):
    src1 = ScanAPI.get_source_by_chain(chain1, addr1)
    src2 = ScanAPI.get_source_by_chain(chain2, addr2)
    diff_source(src1, src2, output)

def diff_uniswap(chain, factory=None, pair=None, router=None):
    peth = Peth.get_or_create(chain)
    if factory and not pair:
        pair = peth.eth_call(factory, "allPairs(uint)->(address)", [0])
    if not factory and pair:
        factory = peth.eth_call(pair, "factory()->(address)")
    
    if factory: 
        # UniswapV2Factory 
        diff_chain_src('eth', '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f', chain, factory, "uni_factory")
    if pair: 
        # UniswapV2Pair
        diff_chain_src('eth', '0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852', chain, pair, "uni_pair")
    if router:
        # UniswapV2Router02
        diff_chain_src('eth', '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', chain, router, "uni_router")

PATTERNS = {
    'uni': diff_uniswap
}

def diff_pattern(*args):
    pattern = args[0]
    assert pattern in PATTERNS
    PATTERNS[pattern](*args[1:])




