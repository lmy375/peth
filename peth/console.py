import ast
import cmd
import json
import os
import re
import time

from hexbytes import HexBytes
from web3 import Web3

# Import all command modules to register them
import peth.commands  # noqa: F401
from peth.core.peth import Peth
from peth.eth.abi import ABI
from peth.eth.bytecode import Code
from peth.eth.utils import convert_value_list, guess_calldata_types
from peth.util.logos import random_logo

from .core.config import config
from .core.registry import command_registry


class PethConsole(cmd.Cmd):
    """
    An interactive command console to use peth tools.
    """

    prompt = "peth > "

    def __init__(self, peth_instance: Peth) -> None:
        super().__init__()
        self.peth: Peth = peth_instance

        self._debug = False

        # Bind all registered commands to this console instance
        command_registry.bind_to_console(self)

    def get_names(self):
        """
        Override to include dynamically registered commands for autocomplete.
        """
        # Get the default names from parent class
        names = cmd.Cmd.get_names(self)

        # Add all registered commands
        for cmd_name in command_registry.get_commands():
            names.append(f"do_{cmd_name}")

        # Remove duplicates and return
        return list(set(names))

    def completenames(self, text, *ignored):
        """
        Override to provide command name completion.
        """
        # Get all command names (without 'do_' prefix)
        dotext = "do_" + text
        commands = [a[3:] for a in self.get_names() if a.startswith(dotext)]
        return commands

    ##################################################################
    # Console related functions.

    @property
    def web3(self):
        return self.peth.web3

    @property
    def eth(self):
        return self.web3.eth

    @property
    def scan(self):
        return self.peth.scan

    def onecmd(self, line):
        try:
            # ! run system shell.
            # ? eval python script.
            if line.startswith("!"):
                line = "sh " + line[1:]
            elif line.startswith("?"):
                line = "py " + line[1:]

            return super().onecmd(line)
        except Exception as e:
            print("Error: ", e)
            if self._debug:
                raise Exception from e

            cmd = line.split()[0]
            super().onecmd(f"help {cmd}")
            return False  # don't stop

    def start_console(self):
        """
        Start a peth console. Catch Ctrl+C.
        """

        print(random_logo())
        print("                           -- https://github.com/lmy375")
        print()
        print("Welcome to the peth shell. Type `help` to list commands.\n")
        while True:
            try:
                self.cmdloop()
                return
            except KeyboardInterrupt:
                print()  # new line.

    def single_command(self, cmd, debug=True):
        """
        Run single command. This will not catch call exception by default.
        """
        if type(cmd) is list:
            cmd = " ".join(cmd)
        else:
            cmd = str(cmd)

        self._debug = debug
        self.onecmd(cmd)

    def do_EOF(self, arg):
        """Handle Ctrl+D to exit the console."""
        print("\nbye!")  # Print a newline and bye message for cleaner exit
        return True

    def emptyline(self):
        """Called when an empty line is entered. Do nothing."""
        pass

    def do_help(self, arg):
        """
        List available commands with "help" or detailed help with "help cmd".
        help category : List commands by category (console, utils, abi, eth, transaction, bytecode, contract)
        """
        if not arg:
            # Show all commands grouped by category
            categories = command_registry.get_categories()
            print("\nAvailable commands by category:\n")

            for category in sorted(categories):
                commands = command_registry.get_commands(category)
                if commands:
                    print(f"  {category.upper()}:")
                    for cmd_name in sorted(commands.keys()):
                        # Get the first line of docstring
                        func = commands[cmd_name]
                        if func.__doc__:
                            doc_line = func.__doc__.strip().split("\n")[0]
                            print(f"    {cmd_name:<20} {doc_line}")
                        else:
                            print(f"    {cmd_name}")
                    print()

            print("Type 'help <command>' for detailed help on a specific command.")
            print("Type 'help <category>' to see commands in that category.")

        elif arg.lower() in command_registry.get_categories():
            # Show commands for a specific category
            category = arg.lower()
            commands = command_registry.get_commands(category)
            print(f"\n{category.upper()} commands:\n")
            for cmd_name in sorted(commands.keys()):
                func = commands[cmd_name]
                if func.__doc__:
                    print(f"  {cmd_name}:")
                    print(f"    {func.__doc__.strip()}")
                    print()
                else:
                    print(f"  {cmd_name}")
        else:
            # Show help for a specific command
            cmd.Cmd.do_help(self, arg)

    ##################################################################
    # Internal functions.

    def _normal_str(self, v, full=False):
        if isinstance(v, bytes):
            v = v.hex()
        v = str(v).splitlines()[0]
        if not full and len(v) > 80:
            v = v[:80] + " ..."
        return v

    def _print_json(self, data, full=False):
        if isinstance(data, list):
            i = 1
            for item in data:
                print("---- [%d] ----" % i)
                self._print_json(item, full)
                i += 1
        elif getattr(data, "items", None):  # dict-like object.
            for k, v in data.items():
                if v:
                    v = self._normal_str(v, full)
                print(" ", k, ":\t", v)
        else:
            print(self._normal_str(data, full))

    def _parse_args(self, arg, typ="auto"):
        """
        Simple command line arguments parser.

        auto: Split to arguments and convert numbers and addresses.

        address: if not address raise an error.
        number: if not number raise an error.
        string: return string

        (type, type, ..)
            Tuple.

        [type]:
            Array.
        """
        if type(arg) is str:
            args = arg.strip().split()
        else:
            assert type(arg) is list
            args = arg

        if typ == "auto":
            return convert_value_list(args)
        elif typ == "address":
            assert Web3.is_address(args[0]), f"{args[0]} not address"
            return Web3.to_checksum_address(args[0])
        elif typ == "number":
            value = ast.literal_eval(args[0])
            assert type(value) is int, f"{args[0]} not number"
            return value
        elif typ == "string":
            return args[0]
        elif type(typ) is list:
            assert len(typ) == 1, "_parse_args: invalid type"
            return [self._parse_args(a, typ[0]) for a in args]
        elif type(typ) is tuple:
            assert len(typ) == len(
                args
            ), f"Invalid args count: {len(typ)} need. {len(args)} found."
            r = []
            for a, t in zip(args, typ):
                r.append(self._parse_args(a, t))
            return r
        else:
            raise Exception("_parse_args: invalid type")

    ##################################################################
    # Helper methods for commands

    def _get_asm_lines(self, chain, addr):
        peth_instance = Peth.get_or_create(chain)
        addr = peth_instance.web3.to_checksum_address(addr)
        return Code.disasm(peth_instance.web3.eth.get_code(addr)).splitlines()

    def _check_alias(self, alias):
        if alias in config.contracts:
            return config.contracts[alias]
        else:
            return self.peth.chain, alias

    def _get_code(self, arg):
        code = None
        if Web3.is_address(arg):
            addr = self.web3.to_checksum_address(arg)
            code = self.web3.eth.get_code(addr).hex()
            if code.startswith("0x"):
                code = code[2:]
        elif os.path.exists(arg):
            solc_out = json.load(open(arg))
            code = solc_out["deployedBytecode"]
        else:
            assert re.match("[a-fA-F0-9xX]+", arg), f"{arg[:10]} is not valid bytecode."
            if arg.startswith("0x"):
                arg = arg[2:]
            code = arg
        # https://docs.soliditylang.org/en/v0.8.10/metadata.html#encoding-of-the-metadata-hash-in-the-bytecode
        if code.endswith("0033"):
            code = code[:106]
            code += "<metadata>"
        return code

    def _code_to_list(self, code):
        r = []
        i = 0
        while i < len(code):
            # add blanks so we have prettier diff file.
            r.append(code[i : i + 64] + " " * 10)
            i += 64
        return r

    def _get_name(self, addr):
        addr = self.web3.to_checksum_address(addr)
        codesize = len(self.web3.eth.get_code(addr))
        if codesize:
            name = self.peth.scan.get_contract_name(addr)
            if name:
                if name == "GnosisSafe":
                    threshold = self.peth.call_contract(addr, "getThreshold()->(uint)")
                    users = self.peth.call_contract(addr, "getOwners()->(address[])")
                    if users is None:
                        total = 0
                    else:
                        total = len(users)
                    return f"GnosisSafe {threshold}/{total}"
                else:
                    return f"{name}"
            else:
                return f"Contract {codesize} bytes"
        else:
            return "EOA"

    def _get_full_name(self, addr):
        return f"{addr} {self._get_name(addr)}"

    def open_cmd(self, arg):
        """Helper method for opening URLs/files - delegates to the open command."""
        self.onecmd(f"open {arg}")

    def _parse_tx_call_args(self, arg):
        args = arg.split()

        to = args[0]
        data = args[1]

        if len(args) >= 3:
            sender = args[2]
        else:
            sender = self.peth.sender

        if len(args) >= 4:
            value = args[4]
        else:
            value = 0

        return to, data, sender, value

    def _get_block(self, number):
        start = time.time()
        while True:
            try:
                return self.eth.get_block(number, True)
            except Exception as e:
                if time.time() - start > 5:  # Error for long time.
                    raise (e)
                else:
                    time.sleep(0.5)

    def _print_block(self, tag, block):
        gas_used_rate = "%0.2f%%" % (100 * block.gasUsed / block.gasLimit)

        txns = block.transactions
        tx_cnt = len(txns)

        if tx_cnt == 0:
            print(f"\t{tag} - Block {block.number}, {tx_cnt} txns")
            return

        gas_used_total = 0
        gas_used_max = 0
        gas_used_min = 10**100

        gas_price_total = 0
        gas_price_max = 0
        gas_price_min = 10**100

        for tx in txns:
            gas_used_total += tx.gas
            if tx.gas > gas_used_max:
                gas_used_max = tx.gas
            if tx.gas < gas_used_min:
                gas_used_min = tx.gas

            gas_price_total += tx.gasPrice

            if tx.gasPrice > gas_price_max:
                gas_price_max = tx.gasPrice
            if tx.gasPrice < gas_price_min:
                gas_price_min = tx.gasPrice

        gas_used_avg = gas_used_total / tx_cnt
        gas_price_avg = gas_price_total / tx_cnt

        gas_desc = "%8d < %8d < %8d" % (gas_used_min, gas_used_avg, gas_used_max)
        GWEI = 10**9
        gas_price_desc = "%0.2f < %0.2f < %0.2f" % (
            gas_price_min / GWEI,
            gas_price_avg / GWEI,
            gas_price_max / GWEI,
        )
        tx_cnt = "%4d" % tx_cnt
        print(
            f"\t{tag} - Block {block.number}, {tx_cnt} txns, gas {gas_desc}, {gas_used_rate} used, price {gas_price_desc} Gwei"
        )

    def _print_decoded_calldata(self, calldata, to=None, sig=None):
        func = self.peth.get_function(to, sig, calldata)

        if func:
            values = func.decode_input(calldata)
            value_map = func.map_values(values)

            print("Method:", func.full)
            print("Arguments:")
            values = func.decode_input(calldata)
            value_map = func.map_values(values)
            ABI.print_value_map(value_map, 4)

        else:
            data = HexBytes(calldata)
            print("No signature found for selector %s." % data[:4].hex())
            data = data[4:]
            if not data:  # No data.
                return
            print("Guessing types ...")
            i = 0
            for offset, typ, value in guess_calldata_types(data):
                print("[%d] +%s   %s   %s" % (i, offset, typ, value))
                i += 1
