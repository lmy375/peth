import cmd
import json
import os

from eth.sigs import ERC20Signatures
from eth.utils import get_4byte_sig
from eth.bytecode import Code
from eth.opcodes import OpCode
from eth.scan import ScanAPI
from util import diff

from .config import config

class PethConsole(cmd.Cmd):

    intro = 'Welcome to the peth shell.   Type help or ? to list commands.\n'
    prompt = 'peth > '

    def __init__(self, peth) -> None:
        super().__init__()
        self.peth = peth
        self.web3 = peth.web3
        self._debug = False

    def do_debug(self, arg):
        self._debug = not self._debug
        print("debug set to", self._debug)

    def _print_json(self, d):
        for k, v in d.items():
            if v:
                v = str(v).splitlines()[0]
                if len(v) > 80:
                    v = v[:80] + ' ...'
            print(' ', k, ":\t", v)        

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except Exception as e:
            print("Error: ", e)
            if self._debug:
                raise Exception from e
            return False # don't stop

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
                "totalSupply() -> (uint256)",
                "name() -> (string)",
                "symbol() -> (string)",
                "decimals() -> (uint8)",
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
e
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

    def do_bye(self, arg):
        """
        Exit the shell.
        """

        print('bye!')
        return True

    do_exit = do_bye
    do_quit = do_bye