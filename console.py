import cmd
import json

from sigs import ERC20Signatures
from utils import get_4byte_sig
from code import Code
from opcodes import OpCode

class PethConsole(cmd.Cmd):

    intro = 'Welcome to the peth shell.   Type help or ? to list commands.\n'
    prompt = 'peth > '

    def __init__(self, peth) -> None:
        super().__init__()
        self.peth = peth
        self.web3 = peth.web3

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
            return False # don't stop

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
            
            # Only search the first basic block.
            if ins.op.is_jumpdest:
                break

            if ins.op is OpCode.PUSH4:
                if ins.opnd == 0xffffffff:
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
                args_sig = ",".join('%s %s' % (i["type"], i["name"]) for i in abi["inputs"])
                func_sig = f"{typ} {name}({args_sig})"
                if "outputs" in abi:
                    return_sig = ",".join('%s %s' % (i["type"], i["name"]) for i in abi["outputs"])
                    func_sig += f" returns({return_sig})"
                func_sig += " " + mut
                print(' ', func_sig)

        except Exception as e:
            print(abi)

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
                value = self.peth.eth_call(
                    "0x0000000000000000000000000000000000000000",
                    arg,
                    sig
                )
                print(sig, '=>', value)
        else:
            addr = args[0]
            func = args[1]
            sig = ERC20Signatures.find_by_name(func)
            assert sig, "Unknown ERC20 view function"
            value = self.peth.eth_call(
                    "0x0000000000000000000000000000000000000000",
                    addr,
                    sig,
                    args[2:]
            )
            print(value)

    def do_bye(self, arg):
        """
        Exit the shell.
        """

        print('bye!')
        return True

    do_exit = do_bye
    do_quit = do_bye