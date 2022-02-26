import cmd
import json
import os
import difflib

from web3 import Web3

from eth.sigs import ERC20Signatures
from eth.utils import get_4byte_sig, sha3_256
from eth.bytecode import Code
from eth.opcodes import OpCode
from core.peth import Peth
from util import diff

from .config import config

class PethConsole(cmd.Cmd):

    intro = 'Welcome to the peth shell.   Type help or ? to list commands.\n'
    prompt = 'peth > '

    def __init__(self, peth: Peth) -> None:
        super().__init__()
        self.peth = peth
        self._debug = False

    @property
    def web3(self):
        return self.peth.web3


    def do_debug(self, arg):
        """
        Toggle debug flag. Once on, the console will raise exceptions instead of catching them.
        """
        self._debug = not self._debug
        print("debug set to", self._debug)

    def _print_json(self, d):
        for k, v in d.items():
            if v:
                v = str(v).splitlines()[0]
                if len(v) > 80:
                    v = v[:80] + ' ...'
            print(' ', k, ":\t", v)        

    def do_chain(self, arg):
        """
        chain : Print chain information.
        chain <chain> : Change chain.
        """
        print("Current:")

        if arg in config:
            self.peth.print_info()
            self.peth = Peth.get_or_create(arg)
            print("Changed:")
        
        self.peth.print_info()

    def onecmd(self, line):
        try:
            # ! run system shell.
            # ? eval python script.
            if line.startswith('!'):
                line = 'sh ' + line[1:]
            elif line.startswith('?'):
                line = 'py ' + line[1:]

            return super().onecmd(line)
        except Exception as e:
            print("Error: ", e)
            if self._debug:
                raise Exception from e
            return False # don't stop

    def do_sha3(self, arg):
        """
        sha3 <string> : Calculate Keccak256 hash.
        """
        print(sha3_256(bytes(arg.strip(), "ascii", "ignore")).hex())

    def do_eth_call(self, arg):
        """
        eth_call <to> <sig_or_name> <arg1> <arg2> ... : call contract with 0x sender.
        """
        sender = '0x0000000000000000000000000000000000000000'
        args = arg.split()
        to = args[0]
        sig_or_name = args[1]
        arg_list = args[2:]
        print(self.peth.eth_call(to, sig_or_name, arg_list, sender))

    def do_rpc_call(self, arg):
        """
        rpc_call <method> <arg1> <arg2> ...
        """
        args = arg.split()
        method = args[0]
        arg_list = args[1:]
        print(self.peth.rpc_call(method, arg_list))

    def do_4byte(self, arg):
        """
        4byte <hex_sig> : query text signature in 4byte database.
        """
        if not arg:
            print("4byte <hex_sig> :query text signature in 4byte database.")
            return

        sigs = get_4byte_sig(arg)
        if sigs:
            print('\n'.join(sigs))
        else:
            print("Not found in 4byte.directory.")

    def do_abi4byte(self, arg):
        """
        abi4byte <addr> : disassemble the code and print all signatures.
        """
        addr = self.web3.toChecksumAddress(arg)
        bytes_code = bytes(self.web3.eth.get_code(addr))
        code = Code(bytes_code)
        
        while True:
            ins = code.next_instruction()

            if ins is None:
                break
            
            if ins.op is OpCode.PUSH4:
                if ins.opnd == 0xffffffff:
                    continue

                if ins.opnd < 0x00ffffff:
                    continue

                sig = hex(ins.opnd)
                sigs = get_4byte_sig(sig)
                sigs = sigs[::-1]
                print(sig, ', '.join(sigs))


    def do_balance(self, arg):
        """
        balance <address> : Get the balance of address.
        """
        addr = self.web3.toChecksumAddress(arg)
        b = self.web3.eth.get_balance(addr)
        print('%s Wei( %0.4f Ether)' % (b, float(self.web3.fromWei(b, 'ether'))))

    def do_nonce(self, arg):
        """
        nonce <address> : Get the nonce
        """
        addr = self.web3.toChecksumAddress(arg)
        print(self.web3.eth.get_transaction_count(addr))

    def do_storage(self, arg):
        """
        storage <address> <slot> : Get storage of address.
        """
        addr, slot = arg.split()
        addr = self.web3.toChecksumAddress(addr)
        slot = int(slot)
        print(self.web3.eth.get_storage_at(addr, slot).hex())

    def do_number(self, arg):
        """
        number : Get the current block number.
        """
        print(self.web3.eth.get_block_number())

    def do_code(self, arg):
        """
        code <address> : Get code of address.
        """
        addr = self.web3.toChecksumAddress(arg)
        print(self.web3.eth.get_code(addr).hex())

    def do_disasm(self, arg):
        """
        disasm <address> : Get assembly code of address.
        """
        addr = self.web3.toChecksumAddress(arg)
        print(Code.disasm(self.web3.eth.get_code(addr)))


    def __get_asm_lines(self, chain, addr):
        peth = Peth.get_or_create(chain)
        addr = peth.web3.toChecksumAddress(addr)
        return Code.disasm(peth.web3.eth.get_code(addr)).splitlines()


    def do_diffasm(self, arg):
        """
        diffasm <chain1> <addr1> <chain2> <addr2> : diff bytecode.
        """
        chain1, addr1, chain2, addr2 = arg.split()
        asm1 = self.__get_asm_lines(chain1, addr1)
        asm2 = self.__get_asm_lines(chain2, addr2)
        s = difflib.SequenceMatcher(None, asm1, asm2)
        similarity = s.ratio()
        d = difflib.HtmlDiff()
        buf = d.make_file(asm1, asm2)
        output_filename = '%s_%s_%s_%s_%0.2f' % (
            chain1, addr1, chain2, addr2, similarity
        )
        if not os.path.isdir('diff'):
            os.makedirs('diff')
        output_filename = os.path.join('diff', output_filename)
        open(output_filename + '.html', 'w').write(buf)
        print("Written to " + output_filename+'.html')

    def do_contract(self, arg):
        """
        contract <address> : print contract information (from Etherscan).
        """
        info = self.peth.scan.get_contract_info(arg)
        self._print_json(info)

        abis = info["ABI"]
        try:
            abis = json.loads(abis)
            print(' ', "=== ABI ===")
            for abi in abis:
                typ = abi["type"]
                name = abi.get("name", "")
                mut = abi.get("stateMutability", "")
                func_sig = f"{typ} {name}"
                if "inputs" in abi:
                    args_sig = ",".join('%s %s' % (i["type"], i["name"]) for i in abi["inputs"])
                    func_sig += f"({args_sig})"
                else:
                    func_sig += "()"

                if "outputs" in abi:
                    return_sig = ",".join('%s %s' % (i["type"], i["name"]) for i in abi["outputs"])
                    func_sig += f" returns({return_sig})"
               
                func_sig += " " + mut
                print(' ', func_sig)

        except Exception as e:
            print(e)
            print(abis)

    def do_erc20(self, arg):
        """
        erc20 <address> : print ERC20 information.
        erc20 <address> <function> <args> : call ERC20 function.
        """
  
        args = arg.split()
        if len(args) == 1:
            sigs = [
                "totalSupply()->(uint256)",
                "name()->(string)",
                "symbol()->(string)",
                "decimals()->(uint8)",
            ]
            for sig in sigs:
                value = self.peth.eth_call(arg, sig)
                print(sig, '=>', value)
        else:
            addr = args[0]
            func = args[1]
            sig = ERC20Signatures.find_by_name(func)
            assert sig, "Unknown ERC20 view function"
            value = self.peth.eth_call(addr, sig, args[2:])
            print(value)

    def do_proxy(self, arg):
        """
        proxy <address>: Print ERC1967 proxy information
        """
        addr = self.web3.toChecksumAddress(arg)
        print("Implementation", self.web3.eth.get_storage_at(addr, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)[12:].hex())
        print("Admin", self.web3.eth.get_storage_at(addr, 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103)[12:].hex())
        print("Rollback", self.web3.eth.get_storage_at(addr, 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143)[12:].hex())
        print("Beacon", self.web3.eth.get_storage_at(addr, 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50)[12:].hex())

    def do_timelock(self, arg):
        """
        timelock <address>: Print TimelockController min delay.
        """
        addr = self.web3.toChecksumAddress(arg)
        secs = self.peth.eth_call(addr, "getMinDelay()->(uint)")
        print("Min Delay: %ds = %0.2fh" % (secs, secs/3600))

    def do_tokenpair(self, arg):
        """
        tokenpair <addr1> <addr2> <factory>: Print token pair information.
        tokenpair <addr1> <addr2> : default factory for eth/bsc
        tokenpair <pair addr>
        """
        args = arg.split()
        pair_addr = None
        factory = None
        if len(args) == 3:
            addr1, addr2, factory = args
        elif len(args) == 2:
            addr1, addr2 = args
        elif len(args) == 1:
            pair_addr = arg

        if pair_addr:
            addr1 = self.peth.eth_call(pair_addr, "token0(address)->(address)", [pair_addr])
            addr2 = self.peth.eth_call(pair_addr, "token1(address)->(address)", [pair_addr])
        else:
            if factory is None:
                if self.peth.chain == 'eth':
                    factory = '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f' # Uniswap Factory
                elif self.peth.chain == 'bsc':
                    factory = '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73' # Pancake Factory
            
            assert factory, "Factory address not specified."
            pair_addr = self.peth.eth_call(factory, "getPair(address,address)->(address)", [addr1, addr2])
            assert pair_addr != "0x0000000000000000000000000000000000000000", "Token pair not found."
        
        print("TokenPair: %s" % pair_addr)

        token0 = self.peth.eth_call(pair_addr, "token0()->(address)")
        token0_name = self.peth.eth_call(token0, "symbol()->(string)")

        token0_decimal = self.peth.eth_call(token0, "decimals()->(uint)")
        token1 = self.peth.eth_call(pair_addr, "token1()->(address)")
        token1_name = self.peth.eth_call(token1, "symbol()->(string)")
        token1_decimal = self.peth.eth_call(token1, "decimals()->(uint)")

        r0, r1, _ = self.peth.eth_call(pair_addr, "getReserves()->(uint112,uint112,uint32)")

        r0 = r0/(10**token0_decimal)
        r1 = r1/(10**token1_decimal)

        print("%s %s %s" % (token0_name, token0, token0_decimal))
        print("%s %s %s" % (token1_name, token1, token1_decimal))
        print("Reseves: %0.4f %s, %0.4f %s" %(r0, token0_name, r1, token1_name))

        print("Price:")
        print("1 %s = %0.4f %s" % (token0_name, r1/r0, token1_name))
        print("1 %s = %0.4f %s" % (token1_name, r0/r1, token0_name))

    def do_graph(self, arg):
        """
        Print contract relation graph.
        """
        if arg:
            self.peth.print_contract_graph(arg)


    def do_diff(self, arg):
        """
        diff <addr1> <addr2>
        diff <chain1> <addr1> <chain2> <addr2>
        
        diff uni <chain> <factory> <pair> <router>
        diff sushi <masterchef>
        diff comp <comptroller implementation>
        diff ctoken <cERC20 implementation>

        # If address is unknown, use 0 as placeholder.
        # eg:
        diff uni bsc 0 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0 0
        """
        args = arg.split()
        if args[0] in diff.PATTERNS:
            args = [None if i == '0' else i for i in args]
            diff.diff_pattern(*args)
            return

        if len(args) == 2:
            addr1 = args[0]
            addr2 = args[1]
            src1 = self.peth.scan.get_source(addr1)
            src2 = self.peth.scan.get_source(addr2)
            diff.diff_source(src1, src2)
        elif len(args) == 4:
            chain1 = args[0]
            addr1 = args[1]
            chain2 = args[2]
            addr2 = args[3]
            diff.diff_chain_src(chain1, addr1, chain2, addr2)
        else:
            print('[!] Invalid args.')
            return

    def do_sh(self, arg):
        """
        Run system shell command.
        """
        os.system(arg)

    def do_py(self, arg):
        """
        Eval python script.
        """
        print(eval(arg))

    def do_open(self, arg):
        """
        Open url or file. 
        """
        self.do_sh("open " + arg)

    def do_bye(self, arg):
        """
        Exit the shell.
        """

        print('bye!')
        return True
    
    def do_url(self, addr):
        """
        url <addr> : Open blockchain explorer of the address.
        """
        if Web3.isAddress(addr):
            url = self.peth.get_address_url(addr)
            print(url)
            self.do_open(url)
        else:
            print("%s is not valid address." % addr)


    def do_common_addresses(self, arg):
        """
        common_addresses: Print some common addresses.
        """

        print("Uniswap ETH/USDT LP (UNI-V2) 0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852 ETH")
        print("UniswapV2Factory 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f ETH")
        print("UniswapV2Router02 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D ETH")
        print("UNI token 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984 ETH")
        print("SushiSwap MasterChef 0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd ETH")
        print("SushiSwap MasterChefV2 0xef0881ec094552b2e128cf945ef17a6752b4ec5d ETH")
        print("Compound Unitroller 0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B ETH")
        print("Compound Comptroller 0xbafe01ff935c7305907c33bf824352ee5979b526 ETH")
        print("Compound USDT (cUSDT) CErc20Delegator proxy 0xf650C3d88D12dB855b8bf7D11Be6C55A4e07dCC9 ETH")
        print("CErc20Delegator 0xa035b9e130f2b1aedc733eefb1c67ba4c503491f ETH")
        print("Synthetix: Staking Rewards (Balancer SNX) 0xFBaEdde70732540cE2B11A8AC58Eb2dC0D69dE10 ETH")
        print("PancakeSwap MasterChef 0x73feaa1eE314F8c655E354234017bE2193C9E24E BSC")
        print("PancakePair 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0 BSC")

    do_exit = do_bye
    do_quit = do_bye