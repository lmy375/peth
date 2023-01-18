import os
from web3 import Web3

from peth.core.peth import Peth
from peth.core import config
from peth.eth.scan import ScanAPI

from .source import ContractSource

def diff_source(src1, src2, output=None):
    src1 = ContractSource(src1)
    src2 = ContractSource(src2)
    if output:
        output = os.path.join(config.DIFF_PATH, output)
    src1.compare(src2, output)

def diff_chain_src(chain1, addr1, chain2, addr2, output=None):
    try:
        print("[*] Diff %s-%s  %s-%s" % (chain1, addr1, chain2, addr2))
        src1 = ScanAPI.get_source_by_chain(chain1, addr1)
        src2 = ScanAPI.get_source_by_chain(chain2, addr2)
        diff_source(src1, src2, output)
    except Exception as e:
        print("[!] diff_chain_src: %s" % e)

def diff_uniswap(chain, factory=None, pair=None, router=None):
    peth = Peth.get_or_create(chain)
    if factory and not pair:
        r = peth.eth_call(factory, "allPairs(uint256)->(address)", [0])
        if Web3.isAddress(r):
            pair = r
            print('[*] Auto find pair contract', r)
    if not factory and pair:
        r = peth.eth_call(pair, "factory()->(address)")
        if Web3.isAddress(r):
            factory = r
            print('[*] Auto find factory contract', r)
    
    if factory: 
        # UniswapV2Factory 
        diff_chain_src('eth', '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f', chain, factory, "uni_factory")
    if pair: 
        # UniswapV2Pair
        diff_chain_src('eth', '0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852', chain, pair, "uni_pair")
    if router:
        # UniswapV2Router02
        diff_chain_src('eth', '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', chain, router, "uni_router")

def diff_sushi(chain, masterchef):
    # MasterChef
    diff_chain_src('eth', '0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd', chain, masterchef)

def diff_comp(chain, comptroller):
    # Comptroller implementation.
    diff_chain_src('eth', '0xbafe01ff935c7305907c33bf824352ee5979b526', chain, comptroller)

def diff_ctoken(chain, ctoken):
    # CErc20Delegator
    diff_chain_src('eth', '0xa035b9e130f2b1aedc733eefb1c67ba4c503491f', chain, ctoken)

PATTERNS = {
    'uni': diff_uniswap,
    "sushi": diff_sushi,
    'comp': diff_comp,
    'ctoken': diff_ctoken
}

def diff_pattern(*args):
    pattern = args[0]
    assert pattern in PATTERNS
    PATTERNS[pattern](*args[1:])




