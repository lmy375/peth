import ast
import cmd
import codecs
import difflib
import json
import os
import re
import time
from datetime import datetime

import requests
from eth_account import Account
from hexbytes import HexBytes
from web3 import Web3

from peth.core.peth import Peth
from peth.core.tracer import GethTracer, TxTrace
from peth.eth.abi import ABI, ABIFunction
from peth.eth.bytecode import Code
from peth.eth.evm import VM, Chain, ForkChain, Transaction
from peth.eth.sigs import Signature
from peth.eth.utils import (
    CoinPrice,
    SelectorDatabase,
    convert_value,
    convert_value_list,
    guess_calldata_types,
    guess_single_calldata,
    keccak256,
    selector_to_sigs,
)
from peth.util import diff
from peth.util.graph import ContractRelationGraph
from peth.util.logos import random_logo

from .core.config import config
from .core.log import logger, logging


class PethConsole(cmd.Cmd):
    """
    An interactive command console to use peth tools.
    """

    prompt = "peth > "

    def __init__(self, peth: Peth) -> None:
        super().__init__()
        self.peth: Peth = peth

        self._debug = False

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

        auto: Split to arguments and covert numbers and addresses.

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
                return self._parse_args(a, t)
            return r
        else:
            raise Exception("_parse_args: invalid type")

    ##################################################################
    # Console related commands, such as configuration commands.

    def do_debug(self, arg):
        """
        Toggle debug flag. Once on, the console will raise exceptions instead of catching them.
        """
        self._debug = not self._debug
        if self._debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        print("debug set to", self._debug)

    def do_chain(self, arg):
        """
        chain : Print configuration of the connected chain.
        chain <name> : Change to new chain.
        """

        print("Current:")
        print("  Chain:", self.peth.chain)
        try:
            print("     Chain ID:", self.peth.web3.eth.chain_id)
            print("     Block number:", self.peth.web3.eth.block_number)
        except Exception:
            pass
        print("  RPC:", self.peth.rpc_url)
        print("  API:", self.peth.api_url)
        print("  Address:", self.peth.address_url)

        if arg in config.chains:
            old_sender = self.peth.sender
            self.peth = Peth.get_or_create(arg)
            self.peth.sender = old_sender  # Keep the sender value.
            print("Changed:")
            print("  Chain:", self.peth.chain)
            try:
                print("     Chain ID:", self.peth.web3.eth.chain_id)
                print("     Block number:", self.peth.web3.eth.block_number)
            except Exception:
                pass
            print("  RPC:", self.peth.rpc_url)
            print("  API:", self.peth.api_url)
            print("  Address:", self.peth.address_url)

        else:
            print("Supported chains: %s" % ", ".join(config.chains.keys()))

    def do_config(self, arg):
        """
        config: Print current settings.
        config raw: Print raw settings.
        config <section> <key> <value>: Change settings.
        """
        args = arg.split()
        if len(args) == 0:
            config.print_config()
        elif args[0] == "raw":
            config.print_ini()
        else:
            assert len(args) == 3
            config.cfg.set(args[0], args[1], args[2])

    def do_sender(self, arg):
        """
        sender <addr> : Set default sender in eth_call.
        """
        print("Current:", self.peth.sender)
        if Web3.is_address(arg):
            self.peth.sender = arg
            print("New:    ", self.peth.sender)

    def do_signer(self, arg):
        """
        signer <private-key>: Set signer for send_tx. DANGEROUS!
        """
        if self.peth.signer:
            print("Current:", self.peth.signer.address)
        else:
            print("Current: Not set.")

        if not arg:
            return

        signer = Account.from_key(arg)
        self.peth.signer = signer
        print("New:    ", self.peth.signer.address)

    ##################################################################
    # Chain-independent utility commands.

    def do_keccak256(self, arg):
        """
        keccak256 <string> : Calculate Keccak256 hash.
        """
        print(keccak256(bytes(arg.strip(), "ascii", "ignore")).hex())

    def do_int(self, arg):
        """
        int <number> : Print number.
        """
        arg = arg.replace(",", "")
        if re.findall("[xXa-fA-f]", arg):
            value = int(arg, 16)
        else:
            value = int(arg)
        print("Value: %s" % value)
        print("Value: %e" % (value / 1.0))
        print("Value/1e6  (USDT): %s" % (value / 1e6))
        print("Value/1e8  (BTC): %s" % (value / 1e8))
        print("Value/1e9  (GWei): %s" % (value / 1e9))
        print("Value/1e18 (Ether): %s" % (value / 1e18))
        print("Hex: %#x" % value)
        print("Hex(Address): %#0.40x" % value)
        print("Hex(Uint256): %0.64x" % value)

    def do_addresses(self, arg):
        """
        addresses: Print some common contract addresses.
        """

        print("%-40s %-10s %s" % ("Name", "Chain", "Address"))
        for name in config.contracts:
            chain, addr = config.contracts[name]
            print("%-40s %-10s %s" % (name, chain, addr))

    def do_tokens(self, arg):
        """
        tokens: Print tokens.
        tokens <search text>: Find tokens.
        """
        tokens = config.tokens[self.peth.chain]
        if arg:
            search_text = arg
        else:
            search_text = ""

        print(
            "%-30s %-10s %-45s %8s %15s"
            % ("Name", "Symbol", "Address", "Decimals", "Price")
        )
        for token in tokens:
            line = "%-30s %-10s %-45s %8s %15s" % (
                token["name"],
                token["symbol"],
                token["address"],
                token["decimals"],
                token["price"],
            )
            if search_text.lower() in line.lower():
                print(line)

    def do_portfolio(self, arg):
        """
        portfolio <address>: Print balance of common tokens (like debank)
        """
        addr = self._parse_args(arg, "address")

        portfolio = self.peth.get_portfolio([addr])
        infos = portfolio.get(addr.lower(), [])

        total = 0
        lines = []
        for asset in infos:
            total += asset["usd"]
            line = "%-30s\t%-10s\t%-45s\t%-10s\t%-20s\t%-20s" % (
                asset["info"]["name"],
                asset["info"]["symbol"],
                asset["info"]["address"],
                asset["info"]["price"],
                asset["balance"],
                asset["usd"],
            )
            lines.append(line)

        print("Total: $%0.2f" % total)
        print(
            "%-30s\t%-10s\t%-45s\t%-10s\t%-20s\t%-20s"
            % ("Name", "Symbol", "Address", "Price", "Balance", "USD")
        )
        for line in lines:
            print(line)

    def do_sh(self, arg):
        """
        Run system shell command.
        """
        os.system(arg)

    def do_py(self, arg):
        """
        Eval python script.
        """
        print(eval(arg.strip()))

    def do_ipython(self, arg=None):
        """
        Start ipython console, you can access `web3`, `eth`, `peth`, `console`

        In [1]: web3.eth.block_number
        Out[1]: 17091456

        In [2]: peth.rpc_url
        Out[2]: 'https://rpc.ankr.com/eth'

        In [3]: console.do_chain('')
        Current:
        Chain: eth
        RPC: https://rpc.ankr.com/eth
        API: https://api.etherscan.io/api?
        Address: https://etherscan.io/address/
        Supported chains: local, eth, ethcn, ethw, etf, bsc, heco, matic, avax, ftm, metis, arb, boba, one, cro, oasis, aoa2, aoa, moonriver, moonbeam, op, gnosis, canto
        """

        peth = self.peth
        web3 = self.web3
        eth = web3.eth
        console = self

        # In ipython env.
        [peth, web3, eth, console]

        __import__("IPython").embed(colors="Linux")

    def do_open(self, arg):
        """
        open <path>: Open url or file.
        """
        self.do_sh("open " + arg)

    def do_exit(self, arg):
        """
        exit: Exit the console.
        """

        print("bye!")
        return True

    def do_time(self, arg):
        """
        time <timestamp> : Convert UNIX timestamp to local datetime.
        time <seconds> : Convert seconds to hours / days.
        """
        if not arg:
            print("Current:", int(time.time()))
            return

        try:
            ts = int(arg)
        except Exception as e:
            print("[!] Invalid timestamp number. %s" % e)
            return

        if ts > 3600 * 24 * 365 * 10:
            # If ts > 10 yrs, it's a timestamp.
            import datetime

            print(datetime.datetime.fromtimestamp(ts))
        else:
            # else it's more likely a time interval.
            print("%d secs" % ts)
            print("= %0.1f hours" % (ts / 3600))
            print("= %0.1f days" % (ts / 3600 / 24))

    def do_aes(self, arg):
        """
        aes enc <plain text> <password>: Encrypt with AES.
        aes dec <hex secret> <password>: Decrypt with AES.

        NOTE: IV used as MD5 of password, which is not so safe.
        """
        args = arg.split()

        # https://www.pycryptodome.org
        import hashlib

        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad

        txt = args[1]
        password = args[2]

        key = pad(bytes(password, "utf-8"), 16)
        iv = hashlib.md5(bytes(password, "utf-8")).digest()

        def do_enc(plain):
            plain = pad(bytes(plain, "utf-8"), 16)
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
            secret = aes.encrypt(plain)
            hex_secret = secret.hex()
            return hex_secret

        def do_dec(hex_secret):
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
            secret = bytes.fromhex(hex_secret)
            plain = unpad(aes.decrypt(secret), 16)
            return plain.decode("utf-8")

        if args[0] == "enc":
            print(do_enc(txt))
        else:
            assert args[0] == "dec", "args[0] is not enc/dec"
            try:
                plain = do_dec(txt)
                print(plain)
            except Exception as e:
                print("[!] %s (Password may be wrong)" % e)

    def do_brain(self, arg):
        """
        brain <password>: Generate brain wallet.
        brain <password> <hash times>: Specify hash times. (Default: 10000000)
        """

        args = arg.split()

        password = args[0]
        if len(args) >= 2:
            count = int(args[1])
        else:
            count = 10000000  # Use a big number.

        print("Key:", repr(password))
        print("Count:", count)

        password = password.encode("utf-8")
        for i in range(count):
            if (i % 100000) == 0:
                print("    %d %% \r" % (100 * i / count), end="")
            password = keccak256(password)

        pk = HexBytes(password).hex()

        print("Private Key:", pk)
        print("Address:", Account.from_key(pk).address)

    ##################################################################
    # ABI utility commands.

    def do_4byte(self, arg):
        """
        4byte <selector> : query text signature in https://openchain.xyz/signatures.
        4byte <text> : query text signature which includes such text in local database.
        """
        db = SelectorDatabase.get()

        if re.match("^[0-9A-Fa-fXx]*$", arg):  # selector
            sigs = db.get_sig_from_selector(arg, False, True)
            if sigs:
                print("\n".join(sigs))
            else:
                print("Selector not found in https://openchain.xyz/signatures.")
        else:
            ret = db.get_sig_from_text(arg)
            full_match = None
            if ret:
                for selector, sigs in ret:
                    if arg in sigs:
                        full_match = (selector, ", ".join(sigs))
                    print("0x%s %s" % (selector, ", ".join(sigs)))

            print("%d item(s) found in 4byte.json." % len(ret))
            if full_match:
                print("Full match: 0x%s %s" % full_match)

    def do_abi_encode(self, arg):
        """
        abi_encode <sig> <args1> <args2> ...
        eg: abi_encode func(uint256,address) 1 0xEEEEE...
        """
        args = arg.split()
        sig = args[0]

        f = ABIFunction(sig)

        if len(args) == 1:  # Only selector.
            print(f.selector.hex())
            return

        args = args[1:]
        args = list(map(convert_value, args))
        print(f.encode_input(args).hex())

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

    def do_abi_decode(self, arg):
        """
        abi_decode <hex>
        abi_decode <hex> <sig>
        """
        args = arg.split()
        hexdata = args[0]
        assert re.match("^[0-9A-Fa-fXx]+$", hexdata), "Invalid hex data. %s" % hexdata

        if len(args) == 2:
            sig = args[1]
        else:
            sig = None

        self._print_decoded_calldata(hexdata, sig=sig)

    ##################################################################
    # Basic ETH commands.

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

    def do_eth_call(self, arg):
        """
        eth_call <to> <calldata> [<sender>] [<value>]
        """
        to, data, sender, value = self._parse_tx_call_args(arg)

        try:
            ret = self.web3.eth.call(
                {
                    "from": self.web3.to_checksum_address(sender),
                    "to": self.web3.to_checksum_address(to),
                    "data": data,
                    "value": value,
                },
                "latest",
            )
            print("returns:")
            print(ret.hex())
        except Exception as e:  # revert or other errors.
            print("error:")
            print(e)

    def do_estimate_gas(self, arg):
        """
        estimate_gas <to> <calldata> [<sender>] [<value>]
        """
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
            value = "0"

        try:
            ret = self.web3.eth.estimate_gas(
                {
                    "from": self.web3.to_checksum_address(sender),
                    "to": self.web3.to_checksum_address(to),
                    "data": data,
                    "value": value,
                },
                "latest",
            )
            print("gas:")
            print(ret)
        except Exception as e:  # revert or other errors.
            print("error:")
            print(e)

    def do_call(self, arg):
        """
        call <to> <sig_or_name> <arg1> <arg2> ... : Call contract.
        """
        args = arg.split()
        to = args[0]
        sig_or_name = args[1]
        arg_list = self._parse_args(args[2:])
        print(self.peth.call_contract(to, sig_or_name, arg_list, silent=False))

    def do_rpc_call(self, arg):
        """
        rpc_call <method> <arg1> <arg2> ...

        eg:
            eth_getBalance <address> latest
            eth_chainId
            eth_blockNumber
            web3_clientVersion
            eth_gasPrice
            txpool_status

        Ref:
        - https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_protocolversion
        - https://geth.ethereum.org/docs/interacting-with-geth/rpc
        """
        args = arg.split()
        method = args[0]
        arg_list = args[1:]
        print(json.dumps(self.peth.rpc_call(method, arg_list), indent=2))

    def do_tx_raw(self, arg):
        """
        tx_raw <txid> : Print transaction information.
        """
        print("Transaction:")
        tx = self.web3.eth.get_transaction(arg)
        self._print_json(tx, True)

        print("Receipt:")
        self._print_json(self.web3.eth.get_transaction_receipt(arg), True)

    def do_address(self, arg):
        """
        address <address> : Print information of the account.
        """
        addr = self.web3.to_checksum_address(arg)
        b = self.web3.eth.get_balance(addr)
        print(
            "Balance: %s Wei( %0.4f Ether)" % (b, float(self.web3.from_wei(b, "ether")))
        )

        print("Nonce:", self.web3.eth.get_transaction_count(addr))

        code_size = len(self.web3.eth.get_code(addr))
        print("Code Size:", code_size)

    def do_storage(self, arg):
        """
        storage <address> [<slot>] : Get storage of address.
        """
        args = arg.split()
        addr = self.web3.to_checksum_address(args[0])
        slot = None
        if len(args) >= 2:
            slot_str = args[1]
            try:
                slot = int(slot_str)
            except Exception:
                try:
                    slot = int(slot_str, 16)
                except Exception:
                    print(f"Error: Invalid slot (must be hex/dec number) {slot_str}")
                    return
        if slot is not None:
            print(hex(slot), ":", self.web3.eth.get_storage_at(addr, slot).hex())
        else:
            for slot in range(0, 0x10):
                print(hex(slot), ":", self.web3.eth.get_storage_at(addr, slot).hex())

    def do_send_tx(self, arg):
        """
        send_tx <data> [<to>] [<value>] : Send an transaction.

        TAKE CARE! YOU MAY GET LOSS!

        Only for test and is NOT replacement for secure wallet such
        as Metamask, Rabby, etc.

        Use `signer` to set your key before `send_tx`.
        """
        assert self.peth.signer, "Use `signer` to set your key."
        args = self._parse_args(arg)
        data = args[0]
        to = None
        value = None
        if len(args) >= 2:
            to = args[1]
        if len(args) >= 3:
            value = args[2]

        tx, signed_tx = self.peth.send_transaction(data, to, value, True)
        print("TX info:")
        self._print_json(tx, True)
        print("Sig info:")
        tx_hash = signed_tx.hash.hex()
        print("  Hash:\t", tx_hash)
        print("  Raw Transaction:\t", signed_tx.rawTransaction.hex())
        print("  r:\t", signed_tx.r)
        print("  s:\t", signed_tx.s)
        print("  v:\t", signed_tx.v)
        print("RPC:", self.peth.rpc_url)

        if input("Enter YES to send:") != "YES":
            print("Cancelled.")
            return

        current_block = self.peth.web3.eth.block_number
        self.peth.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"Sent {tx_hash}. Current block {current_block}")
        while True:
            new_block = self.peth.web3.eth.block_number
            if new_block == current_block:
                time.sleep(1)
                continue

            print(f"New block {new_block}")
            current_block = new_block
            try:
                rcpt = self.web3.eth.get_transaction_receipt(tx_hash)
                try:
                    self.do_tx(tx_hash)
                except Exception:
                    pass
                print("Full Receipt:")
                self._print_json(rcpt, True)
                break
            except Exception as e:
                print(e)

    def do_log(self, args):
        """
        log [<address>] [<topic 0>] [<topic 1>] [<topic 2>] [<topic 3>] [loop_count] [block_count]
           Print raw event log:
              tx_hash, address, topics, data

           The search starts from the latest block. Run a loop:
           - Each step scans `block_count` blocks. (Default: 100)
           - Repeat `loop_count` times. (Default: 100)
        """
        address = None
        topics = []
        step = -1
        count = -1

        for arg in args.split():
            if arg in ["-", "null", "None"]:
                topics.append(None)
                continue

            if address is None and len(arg) in (40, 42):
                address = arg
            elif len(arg) < 20:
                if count == -1:
                    count = int(arg)
                else:
                    step = int(arg)
            else:
                if arg.startswith("0x"):
                    arg = arg[2:]
                if len(arg) != 64:
                    arg = arg.rjust(64, "0")
                arg = "0x" + arg
                topics.append(arg)

        step = 100 if step == -1 else step
        count = 100 if count == -1 else count
        print("Search start")
        print(f" - log {step} blocks * {count} times")
        print(f" - address {address}")
        print(f" - topics {' '.join(topics)}:")

        logs = self.peth.get_logs(address, topics, step=step, count=count)
        for log in logs:
            if log.removed:
                continue

            tx_hash = log.transactionHash.hex()
            address = log.address
            data = log.data

            print("txid", tx_hash)
            print("\t address", address)
            for i, topic in enumerate(log.topics):
                print(f"\t topic[{i}] {topic.hex()}")
            print("\t data", data)

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

    def do_status(self, arg=None):
        """
        status: Run a infinite loop and print block and txs information.
        """

        cur = self._get_block("latest")

        start_time = time.time()
        start_block_number = cur.number

        while True:
            total_blocks = cur.number - start_block_number or 1
            total_time = (time.time() - start_time) or 1
            print(
                f"{datetime.now()} {total_blocks/total_time :.2f} b/s {total_time/total_blocks :.2f} s/b"
            )

            self._print_block("latest ", cur)

            while True:
                pending = self._get_block("pending")

                if (
                    pending.number and pending.number <= cur.number
                ):  # Not valid pending.
                    continue

                self._print_block("pending", pending)

                new_cur = self._get_block("latest")
                if new_cur.number >= cur.number + 1:  # new block found.
                    cur = new_cur
                    break
                else:
                    if self.peth.chain == "eth":
                        time.sleep(1)
                    else:
                        time.sleep(0.2)

    def do_blocks(self, arg=None):
        print("Blocks:")

        finalized_block = self._get_block("finalized")
        self._print_block("finalized", finalized_block)

        safe_block = self._get_block("safe")
        self._print_block("safe", safe_block)

        latest_block = self._get_block("latest")
        self._print_block("latest", latest_block)

        safe_block_confs = latest_block.number - safe_block.number
        finalized_block_confs = latest_block.number - finalized_block.number

        safe_block_time = latest_block.timestamp - safe_block.timestamp
        finalized_block_time = latest_block.timestamp - finalized_block.timestamp

        print(
            f"Block rate: {finalized_block_confs/(finalized_block_time or 1) :.2f} b/s {finalized_block_time/(finalized_block_confs or 1) :.2f} s/b"
        )
        print(
            f"Safe gap: {safe_block_confs} blocks, {safe_block_time :.2f} secs = {safe_block_time/60 :.2f} mins"
        )
        print(
            f"Finalized gap: {finalized_block_confs} blocks, {finalized_block_time :.2f} secs = {finalized_block_time/60 :.2f} mins"
        )

    ##################################################################
    # Common used eth_call alias command.

    def do_run(self, arg: str):
        """
        run <your_path>.sol : Run the code with eth_call.

        pragma solidity ^0.8.13;

        contract Executor {
            constructor() public payable {}

            function run() external returns(address, address, address){
                //////////////////////
                // ADD YOUR CODE HERE.
                // It's OK to change the return type or add more functions
                // or contract.
                // But the `Executor` contract and `run()` function must be
                // reserved.
                //////////////////////
                return (msg.sender, tx.origin, address(this));
            }
        }
        """
        assert arg.endswith(".sol"), ".sol file needed but get %s." % arg
        assert os.path.exists(arg), "File %s not exists." % arg
        code = open(arg).read()
        r = self.peth.run_solidity(code)
        print(r)

    def do_view(self, arg):
        """
        view <contract> <name> [<type>] [<length>] : Call property-like view method.

        eg:
            view <contract> admin         => eth_call <contract> admin()
            view <contract> admin address => eth_call <contract> admin()->(address)
            view <contract> name string => eth_call <contract> name()->(string)
            view <contract> addrs address addrs_length => eth_call <contract> addrs(uint256)->(address) i
        """
        args = arg.split()
        to = args[0]
        name = args[1]
        typ = None
        if len(args) >= 3:
            typ = args[2]
            if len(args) >= 4:
                length = args[3]
                try:
                    length = int(length)
                except Exception:
                    length = self.peth.get_view_value(to, name, "uint256")

                sig = f"{name}(uint256)->({typ})"
                for i in range(length):
                    value = self.peth.call_contract(to, sig, [i])
                    print(f"[{i}]\t{value}")

                    if not value:
                        print("None found. Stop.")
                        return
                return
        print(self.peth.get_view_value(to, name, typ))

    def do_erc20(self, arg):
        """
        erc20 <address> : print ERC20 information.
        erc20 <address> <function> <args> : call ERC20 function.
        """

        args = arg.split()
        if len(args) == 1:
            methods = [
                ("Name:", "name()->(string)"),
                ("Symbol:", "symbol()->(string)"),
                ("decimals:", "decimals()->(uint256)"),
                ("totalSupply:", "totalSupply()->(uint256)"),
            ]

            token = self._parse_args(arg, "address")
            for name, method in methods:
                print(name, self.peth.call_contract(token, method))

        else:
            addr = args[0]
            func = args[1]
            call_args = convert_value_list(args[2:])

            sigs = [
                "totalSupply() -> (uint256)",
                "balanceOf(address) -> (uint256)",
                "allowance(address, address) -> (uint256)",
                "name() -> (string)",
                "symbol() -> (string)",
                "decimals() -> (uint8)",
            ]
            try:
                sig = next(s for s in sigs if s.startswith(func))
            except StopIteration:
                print(f"{func} not a valid ERC20 method")
                return

            value = self.peth.call_contract(addr, sig, call_args)
            print(value)

    def do_proxy(self, args):
        """
        proxy <address> [<address>]: Print ERC1967 proxy information
        """

        def _print_slot_as_address(name, slot):
            bytes32 = self.web3.eth.get_storage_at(addr, slot)
            if int(bytes32.hex(), 16) != 0:
                _addr = bytes32[12:].hex()
                print(f"{name}: {self._get_full_name(_addr)}")

        for arg in args.split():
            addr = self.web3.to_checksum_address(arg)
            impl = self.web3.eth.get_storage_at(
                addr, 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
            )[12:].hex()
            admin = self.web3.eth.get_storage_at(
                addr, 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103
            )[12:].hex()
            beacon = self.web3.eth.get_storage_at(
                addr, 0xA3F0AD74E5423AEBFD80D3EF4346578335A9A72AEAEE59FF6CB3582B35133D50
            )[12:].hex()

            if int(impl, 16) == 0 and int(beacon, 16) == 0:
                print(f"{addr} may be not an ERC-1967 Proxy")
                print("Implementation:", self._get_full_name(impl))
                print("Admin:", self._get_full_name(admin))
                # Print first slots, may be used as customized proxy.
                _print_slot_as_address("Slot[0]", 0)
                _print_slot_as_address("Slot[1]", 1)
                _print_slot_as_address("Slot[2]", 2)
                _print_slot_as_address("Slot[3]", 3)
            else:
                print(f"{addr} is an ERC-1967 Proxy")
                print("Implementation:", self._get_full_name(impl))

                name = self._get_full_name(admin)
                print("Admin:", name)
                print("Beacon:", self._get_full_name(beacon))
                _print_slot_as_address(
                    "Rollback",
                    0x4910FDFA16FED3260ED0E7147F7CC6DA11A60208B5B9406D12A635614FFD9143,
                )

                if "ProxyAdmin" in name:
                    print("ProxyAdmin owner:")
                    self.do_owner(admin)

    def do_proxy_all(self, args):
        """
        proxy_all <address> [<address>]: Only print proxy addresses.
        """
        for arg in args.split():
            addr = self.web3.to_checksum_address(arg)
            impl = self.web3.eth.get_storage_at(
                addr, 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
            )[12:].hex()
            if int(impl, 16) != 0:
                name = self.peth.scan.get_contract_name(addr)
                if not name:
                    name = ""
                print(f"Proxy {name} {addr} impl {impl}")

    def do_owner(self, arg):
        """
        owner <ownable-contract-address>: Print contract owner.
        """
        addr = self.web3.to_checksum_address(arg)
        try:
            owner = self.peth.call_contract(addr, "owner()->(address)")
            print("Owner: %s" % self._get_full_name(owner))
        except Exception as e:
            print(f"Ensure your input is a Ownable contract address. {e}")

    def do_safe(self, arg):
        """
        safe <gnosis-proxy-address>: Print Gnosis information.
        """
        addr = self.web3.to_checksum_address(arg)

        print("Version:", self.peth.call_contract(addr, "VERSION()->(string)"))

        threshold = self.peth.call_contract(addr, "getThreshold()->(uint)")
        users = self.peth.call_contract(addr, "getOwners()->(address[])")
        if users:
            print("Policy: %s/%s" % (threshold, len(users)))
            print("Owners:")
            for u in users:
                print(" ", self._get_full_name(u))

        print("Impl:", self.peth.call_contract(addr, "masterCopy()->(address)"))

        fallback = self.web3.eth.get_storage_at(
            addr, 0x6C9A6C4A39284E37ED1CF53D337577D14212A4870FB976A4366C693B939918D5
        )[12:].hex()
        print("Fallback handler:", self._get_full_name(fallback))

        guard = self.web3.eth.get_storage_at(
            addr, 0x4A204F620C8C5CCDCA3FD54D003BADD85BA500436A431F0CBDA4F558C93C34C8
        )[12:].hex()
        print("Guard:", self._get_full_name(guard))

        modules = self.peth.call_contract(
            addr,
            "getModulesPaginated(address,uint256)->(address[],address)",
            ["0x0000000000000000000000000000000000000001", 100],
        )[0]
        if modules:
            print("Modules:")
            for m in modules:
                print(" ", self._get_full_name(m))

    def do_timelock(self, arg):
        """
        timelock <address>: Print TimelockController min delay.
        """
        addr = self.web3.to_checksum_address(arg)
        try:
            secs = self.peth.call_contract(addr, "getMinDelay()->(uint)", silent=True)
            print("Min Delay: %ds = %0.2fh" % (secs, secs / 3600))
        except Exception:
            pass

        try:
            secs = self.peth.call_contract(addr, "MINIMUM_DELAY()->(uint)", silent=True)
            print("Min Delay: %ds = %0.2fh" % (secs, secs / 3600))
        except Exception:
            pass

        try:
            secs = self.peth.call_contract(addr, "MAXIMUM_DELAY()->(uint)", silent=True)
            print("Max Delay: %ds = %0.2fh" % (secs, secs / 3600))
        except Exception:
            pass

        try:
            secs = self.peth.call_contract(addr, "delay()->(uint)", silent=True)
            print("Current Delay: %ds = %0.2fh" % (secs, secs / 3600))
        except Exception:
            pass

        try:
            admin = self.peth.call_contract(addr, "admin()->(address)", silent=True)
            print("Admin: %s" % self._get_full_name(admin))
        except Exception:
            pass

    def do_pair(self, arg):
        """
        pair <addr1> <addr2> <factory>: Print token pair information.
        pair <addr1> <addr2> : default factory for eth/bsc
        pair <pair addr>
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
            addr1 = self.peth.call_contract(pair_addr, "token0()->(address)")
            addr2 = self.peth.call_contract(pair_addr, "token1()->(address)")
        else:
            if factory is None:
                if self.peth.chain == "eth":
                    factory = (
                        "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"  # Uniswap Factory
                    )
                elif self.peth.chain == "bsc":
                    factory = (
                        "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"  # Pancake Factory
                    )

            assert factory, "Factory address not specified."
            pair_addr = self.peth.call_contract(
                factory, "getPair(address,address)->(address)", [addr1, addr2]
            )
            assert (
                pair_addr != "0x0000000000000000000000000000000000000000"
            ), "Token pair not found."

        print("TokenPair:", pair_addr)

        token0_name = self.peth.call_contract(addr1, "symbol()->(string)")
        token0_decimal = self.peth.call_contract(addr1, "decimals()->(uint)")

        token1_name = self.peth.call_contract(addr2, "symbol()->(string)")
        token1_decimal = self.peth.call_contract(addr2, "decimals()->(uint)")

        print("%s %s %s" % (token0_name, addr1, token0_decimal))
        print("%s %s %s" % (token1_name, addr2, token1_decimal))

        # r0, r1, _ = self.peth.call_contract(
        #     pair_addr, "getReserves()->(uint112,uint112,uint32)")
        r0 = self.peth.call_contract(addr1, "balanceOf(address)->(uint)", [pair_addr])
        r1 = self.peth.call_contract(addr2, "balanceOf(address)->(uint)", [pair_addr])

        fee = self.peth.call_contract(pair_addr, "fee()->(uint)", silent=True)
        if fee:
            print("V3 Fee: %0.2f%%" % (fee / 1e4))

        r0 = r0 / (10**token0_decimal)
        r1 = r1 / (10**token1_decimal)
        print("Reseves: %0.4f %s, %0.4f %s" % (r0, token0_name, r1, token1_name))

        if fee is None:
            # Only for V2.
            print("V2 Price:")
            print("1 %s = %0.4f %s" % (token0_name, r1 / r0, token1_name))
            print("1 %s = %0.4f %s" % (token1_name, r0 / r1, token0_name))

    def do_factory(self, arg):
        """
        factory <factory address>
        """
        factory = self.web3.to_checksum_address(arg)
        size = self.peth.call_contract(factory, "allPairsLength()->(uint256)")
        print("%d pairs found." % size)
        for i in range(size):
            try:
                pair = self.peth.call_contract(
                    factory, "allPairs(uint256)->(address)", [i]
                )
                print("[%d] %s" % (i, pair))
                self.do_pair(pair)
            except Exception as e:
                print("[*] %s" % e)

    def do_oracle(self, arg):
        """
        oracle <EACAggregatorProxy>[,<EACAggregatorProxy>] : Print ChainLink oracle aggregator information.
        """
        i = 1
        cnt = len(arg.split(","))
        for addr in arg.split(","):
            addr = addr.strip()
            addr = self.web3.to_checksum_address(addr)
            try:
                if cnt > 1:
                    print("---- [%s] ----" % i)
                    i += 1

                aggr = self.peth.call_contract(addr, "aggregator()->(address)")
                if aggr is None:
                    aggr = addr
                else:
                    print("Aggregator:", aggr)
                    print(
                        "Proxy Owner:",
                        self.peth.call_contract(addr, "owner()->(address)"),
                    )

                print(
                    "Aggregator Owner:",
                    self.peth.call_contract(aggr, "owner()->(address)"),
                )

                print(
                    "Version:",
                    self.peth.call_contract(aggr, "version()->(uint256)"),
                )

                print(
                    "Description:",
                    self.peth.call_contract(aggr, "description()->(string)"),
                )

                dec = self.peth.call_contract(aggr, "decimals()->(uint8)")
                print("Decimals:", dec)

                latest = self.peth.call_contract(aggr, "latestAnswer()->(int256)")
                print("Latest Answer: %d (%0.2f)" % (latest, latest / (10**dec)))

                max = self.peth.call_contract(aggr, "maxAnswer()->(int192)")
                print("Max Answer: %d (%0.2f)" % (max, max / (10**dec)))

                min = self.peth.call_contract(aggr, "minAnswer()->(int192)")
                print("Min Answer: %d (%0.2f)" % (min, min / (10**dec)))

                transmitters = self.peth.call_contract(
                    aggr, "transmitters()->(address[])"
                )
                print("%d Transmitters:" % len(transmitters))
                for addr in transmitters:
                    print(" ", addr)

            except Exception:
                pass

    ##################################################################
    # Transaction tools.

    def do_tx(self, arg):
        """
        tx <txid> : Decode call data.
        tx <addr> <data>
        tx <sig> <data>
        """
        args = arg.split()
        if len(args) == 1:
            txid = arg
            info = self.web3.eth.get_transaction(txid)
            sender = info["from"]
            to = info["to"]
            data = info["input"]
            r = self.web3.eth.get_transaction_receipt(txid)
            if to is None:
                contract_address = r["contractAddress"]
                print("%s creates contract %s" % (sender, contract_address))
            else:
                print("From: %s\nTo: %s" % (sender, to))
                if data:
                    self._print_decoded_calldata(data, to)

            if r.status == 0:
                print("Tx reverted.")
                return

            erc20_trans = []
            for item in r.logs:
                address_names = {sender: "sender", to: "to"}

                # Transfer event.
                if (
                    len(item.topics) == 3
                    and item.topics[0].hex()
                    == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                ):
                    src = self.web3.to_checksum_address(item.topics[1][-20:])
                    src = address_names.get(src, src)
                    dst = self.web3.to_checksum_address(item.topics[2][-20:])
                    dst = address_names.get(dst, dst)

                    amount = self.web3.to_int(hexstr=item.data.hex())
                    token = item.address
                    symbol = self.peth.call_contract(
                        token, "symbol()->(string)", silent=True
                    )
                    if symbol is None:
                        symbol = "Unknown"
                    token = "%s(%s)" % (symbol, token)
                    msg = " ".join(map(str, (token, "%s->%s" % (src, dst), amount)))
                    erc20_trans.append(msg)

            if erc20_trans:
                print("ERC20 Transfers:")
                for msg in erc20_trans:
                    print(" ", msg)

        else:
            assert len(args) == 2, "Invalid args number."
            sig_or_addr = args[0]
            data = args[1]

            if Web3.is_address(sig_or_addr):
                self._print_decoded_calldata(data, sig_or_addr, None)
            else:
                self._print_decoded_calldata(data, None, sig_or_addr)

    def do_idm(self, arg):
        """
        idm <addr>  : Print the first 10 IDM messages related to the account.
        idm <addr> <count>  : Print the first n IDM messages
        idm <addr> <count> <asc/desc>  : Print the last n IDM messages
        idm <addr> <count> <asc/desc> <startblock> <endblock> : Print IDM messages between specified blocks.
        """
        args = arg.split()
        assert len(args) >= 1
        addr = args[0]
        count = 10
        startblock = None
        endblock = None
        reverse = False

        if len(args) >= 2:
            count = int(args[1])
        if len(args) >= 3:
            reverse = args[2] == "desc"
        if len(args) >= 5:
            startblock = int(args[3])
            endblock = int(args[4])

        txs = self.peth.scan.get_txs_by_account(
            addr, startblock, endblock, count, reverse
        )

        if not txs:
            print("No txs.")
            return

        i = 0
        for tx in txs:

            sender = tx["from"]
            to = tx["to"]
            data = tx["input"]
            value = int(tx["value"])

            data = data[2:]  # remove 0x
            if len(data) <= 8 or "00" in data:
                continue

            if sender == addr:
                sender = "Hacker"
            if to == addr:
                to = "Hacker"

            i += 1
            print("---- [%d] %s to %s (%0.4f)----" % (i, sender, to, value / 1e18))

            try:
                msg = codecs.decode(data, "hex").decode("utf-8")
                print(msg)
            except Exception:
                print("Decode failed.")

    def do_txs(self, arg):
        """
        txs <addr>  : Print the first 10 txs of the account.
        txs <addr> <count>  : Print the first n txs of the account.
        txs <addr> <count> <asc/desc>  : Print the last n txs of the account.
        txs <addr> <count> <asc/desc> <startblock> <endblock> : Print txs between specified blocks.
        """
        args = arg.split()
        assert len(args) >= 1
        addr = args[0]
        count = 10
        startblock = None
        endblock = None
        reverse = False

        if len(args) >= 2:
            count = int(args[1])
        if len(args) >= 3:
            reverse = args[2] == "desc"
        if len(args) >= 5:
            startblock = int(args[3])
            endblock = int(args[4])

        txs = self.peth.scan.get_txs_by_account(
            addr, startblock, endblock, count, reverse
        )

        if not txs:
            print("No txs.")
            return

        i = 0
        for tx in txs:
            i += 1
            print("---- [%d] %s %s ----" % (i, tx["hash"], tx["blockNumber"]))

            sender = tx["from"]
            to = tx["to"]
            data = HexBytes(tx["input"])
            contract = tx["contractAddress"]
            value = tx["value"]

            if Web3.is_address(to):
                to_name = self.peth.scan.get_address_name(to)
            else:
                to_name = to

            if Web3.is_address(contract):
                contract = self.peth.scan.get_address_name(contract)

            if contract:
                print("%s creates contract %s" % (sender, contract))
                continue

            if value:
                print("%s -> %s value %s" % (sender, to_name, value))
            else:
                print("%s -> %s" % (sender, to_name))

            if len(data) > 4:
                try:
                    self._print_decoded_calldata(data, to)
                except Exception as e:
                    print("Error:", e)

    def do_aml(self, arg):
        """
        aml <address> : Print funding chain related to the address.
        """
        addr = Web3.to_checksum_address(arg)

        print("Start", addr)
        i = 1
        while True:
            if not Web3.is_address(addr):
                break

            is_int_tx, tx = self.scan.get_first_tx(addr)
            if tx is None:
                break

            if is_int_tx:
                txid = tx["hash"]
                tx = self.web3.eth.get_transaction(txid)
                sender = tx["from"]
                to = tx["to"]
                name = self.scan.get_contract_name(to)

                print(f"[{i}] {sender} calls contract {name}({to}) in {txid}")

                if "Tornado" in name:
                    # Tornado.cash found, no sense to continue searching.
                    break
            else:
                sender = tx["from"]
                to = tx["to"]
                value = int(tx["value"])
                ethers = "%0.5f" % self.web3.from_wei(value, "ether")
                print(f"[{i}] {sender} sends {to} {ethers} ETH")

            addr = sender
            i += 1

        print("End")

    def do_tx_replay(self, arg):
        """
        tx_replay <txid> [<new sender>] : Try to replay the tx with different sender.
        (To check if the tx has a msg.sender check.)
        """
        args = arg.split()
        txid = args[0]
        if len(args) >= 2:
            sender = args[1]
            assert Web3.is_address(sender), "Invalid address %s" % sender
        else:
            # Just a random selected new address with no ETH.
            sender = "0x4459cD4ef34A3DCeC05b32e4f76A6e4306176e6f"

        tx = self.web3.eth.get_transaction(txid)
        block_number = tx["blockNumber"] - 1
        print(
            "Replay(eth_call) %s at block %s with sender %s:"
            % (txid, block_number, sender)
        )

        try:
            r = self.web3.eth.call(
                {
                    # Just a random selected new address with no ETH.
                    "from": "0x4459cD4ef34A3DCeC05b32e4f76A6e4306176e6f",
                    "to": tx["to"],
                    "data": tx["input"],
                    "value": tx["value"],
                },
                block_number,
            )
            print("Replay succeeded. eth_call returns:")
            print(r)
        except Exception as e:  # revert or other errors.
            print("Replay failed.")
            print(e)

    def do_trace_tx(self, arg):
        """
        trace_tx <txid>: Print transaction trace. Note: A Debug RPC is required.
        """
        txid = arg.strip()
        js = "legacy_tracer.js"
        tracer = GethTracer(self.peth.rpc_url, js)
        result = tracer.trace_transaction(txid)
        trace = TxTrace(self.peth.chain, result)
        trace.print()

    def do_trace_call(self, arg):
        """
        trace_call <to> <calldata> [<sender>] [<value>]: Perform a call and print trace. Note: A Debug RPC is required.
        """
        to, data, sender, value = self._parse_tx_call_args(arg)

        js = "legacy_tracer.js"
        tracer = GethTracer(self.peth.rpc_url, js)
        result = tracer.trace_call(
            {"to": to, "from": sender, "data": data, "value": value}
        )
        trace = TxTrace(self.peth.chain, result)
        trace.print()

    def do_evm_trace_tx(self, arg):
        """
        evm_trace_tx <txid>:
            Simulate the transaction in a simple built-in EVM and print transaction trace.
            Please note that the simulation results may differ from the actual results because:
                1. This simple EVM does not measure gas.
                2. It does not support precompile contracts.
                3. The transaction will be simulated in the block prior to the one it is in.
        """
        txid = arg.strip()
        tx = self.web3.eth.get_transaction(txid)
        block_number = tx["blockNumber"] - 1

        # Chain.debug = True
        # VM.debug = True
        VM.trace = True

        chain = Chain(ForkChain(self.web3, block_number))

        # from .eth.evm.inspector import Inspector
        # ins = Inspector(chain, self.peth)
        r = chain.apply_transaction(
            Transaction(
                sender=tx["from"],
                to=tx["to"],
                value=tx["value"],
                data=HexBytes(tx["input"]),
            )
        )
        # ins.print_call_trace()
        r.trace.print(9)

    def do_evm_trace_call(self, arg):
        """
        evm_trace_call <to> <calldata> [<sender>] [<value>]:
            Simulate the transaction in a simple built-in EVM and print transaction trace.
        """
        to, data, sender, value = self._parse_tx_call_args(arg)
        # Chain.debug = True
        # VM.debug = True
        VM.trace = True

        chain = Chain(ForkChain(self.web3))

        # from .eth.evm.inspector import Inspector
        # ins = Inspector(chain, self.peth)

        r = chain.apply_transaction(
            Transaction(sender=sender, to=to, value=value, data=HexBytes(data))
        )
        # ins.print_call_trace()
        r.trace.print(9)

    ##################################################################
    # Bytecode tools.

    def do_abi4byte(self, arg):
        """
        abi4byte <addr> : disassemble the code and print all signatures.
        """
        addr = Web3.to_checksum_address(arg)
        selectors = self.peth.get_selectors(addr)
        for selector in selectors:
            sig = "0x" + selector.hex()
            sigs = selector_to_sigs(sig)
            sigs = sigs[::-1]
            typ = ""
            value = ""
            if sigs:
                func_sig = sigs[0]
                if len(ABIFunction(func_sig).inputs) == 0:
                    value = self.peth.call_contract(addr, func_sig, silent=True)
                    if value is None:
                        value = ""
                    else:
                        typ, value = guess_single_calldata(value)

            print(sig, ", ".join(sigs), " " * 10, "\t", typ, value)

    def do_disasm(self, arg):
        """
        disasm <address> : Get assembly code of address.
        """
        addr = self.web3.to_checksum_address(arg)
        print(Code.disasm(self.web3.eth.get_code(addr)))

    def _get_asm_lines(self, chain, addr):
        peth = Peth.get_or_create(chain)
        addr = peth.web3.to_checksum_address(addr)
        return Code.disasm(peth.web3.eth.get_code(addr)).splitlines()

    def do_diffasm(self, arg):
        """
        diffasm <chain1> <addr1> <chain2> <addr2> : diff bytecode.
        """
        chain1, addr1, chain2, addr2 = arg.split()
        asm1 = self._get_asm_lines(chain1, addr1)
        asm2 = self._get_asm_lines(chain2, addr2)
        s = difflib.SequenceMatcher(None, asm1, asm2)
        similarity = s.ratio()
        d = difflib.HtmlDiff()
        buf = d.make_file(asm1, asm2)
        output_filename = "%s_%s_%s_%s_%0.2f" % (
            chain1,
            addr1,
            chain2,
            addr2,
            similarity,
        )

        if not os.path.isdir(config.diff_path):
            os.makedirs(config.diff_path)
        output_filename = os.path.join(config.diff_path, output_filename)
        open(output_filename + ".html", "w").write(buf)
        print("Written to " + output_filename + ".html")

    ##################################################################
    # Contract source tools.

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

    def do_name(self, arg):
        """
        name <address> : the contract name.
        """
        if self.web3.is_address(arg):
            print(self._get_full_name(arg))
        else:
            print("Invalid address format.")

    def do_contract(self, arg):
        """
        contract <address> : print contract information (from Etherscan).
        """
        addr = self.web3.to_checksum_address(arg)
        info = self.peth.scan.get_contract_info(arg)

        if info is None:
            print("Contract not verified. Run abi4byte ..")
            self.do_abi4byte(addr)
            return

        self._print_json(info)

        abis = info["ABI"]
        try:
            abi_json = json.loads(abis)
            print(" ", "=== CALLED ===")
            contract = self.web3.eth.contract(address=addr, abi=abi_json)

            others = []
            for item in abi_json:
                if item["type"] == "fallback":
                    others.append("fallback()")
                    break

            for func in contract.all_functions():
                sig = Signature.from_abi(func.abi)

                if len(sig.inputs) == 0:
                    try:
                        ret = func().call()
                    except Exception as e:
                        print(
                            " ",
                            f"[*] Error in calling {sig}",
                            e,
                        )
                        continue
                    print(" ", f"{sig} => {ret}")
                else:
                    others.append(sig)

            print(" ", "=== OTHERS ===")
            for s in others:
                print(" ", s)

        except Exception as e:
            print(e)
            print(abis)

    def do_graph(self, arg):
        """
        graph <addr1> [<addr2> <addr3> ... ]: Print contract relation graph.
        """
        if arg:
            addrOrList = arg.split()
            if type(addrOrList) is list:
                assert len(addrOrList) > 0, "peth.print_contract_graph: addrs is empty."
                root = addrOrList[0]
                addrs = addrOrList
            else:
                root = addrOrList
                addrs = [addrOrList]

            graph = ContractRelationGraph(Web3.to_checksum_address(root), self)
            for addr in addrs:
                addr = Web3.to_checksum_address(addr)
                graph.visit(addr, False)
            graph.print_assets()
            print("=====================")
            print(graph.dump())
            print("=====================")
            print("Open http://relation-graph.com/#/options-tools and paste the json.")

    def _check_alias(self, alias):
        if alias in config.contracts:
            return config.contracts[alias]
        else:
            return self.peth.chain, alias

    def do_diff(self, arg):
        """
        diff <addr1/alias> <addr2/alias>
        diff <chain1> <addr1> <chain2> <addr2>

        diff uni <chain> <factory> <pair> <router>
        diff sushi <chain> <masterchef>
        diff comp <chain> <comptroller implementation>
        diff ctoken <chain> <cERC20 implementation>

        # If address is unknown, use 0 as placeholder.
        # eg:
        diff uni bsc 0 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0 0
        """
        args = arg.split()
        if args[0] in diff.PATTERNS:
            args = [None if i == "0" else i for i in args]
            diff.diff_pattern(*args)
            return

        if len(args) == 2:
            chain1, addr1 = self._check_alias(args[0])
            chain2, addr2 = self._check_alias(args[1])
            diff.diff_chain_src(chain1, addr1, chain2, addr2)
        elif len(args) == 4:
            chain1 = args[0]
            addr1 = args[1]
            chain2 = args[2]
            addr2 = args[3]
            diff.diff_chain_src(chain1, addr1, chain2, addr2)
        else:
            print("[!] Invalid args.")
            return

    def do_download_json(self, arg):
        """
        download_json <addr> [<output_dir>]: Download solc input json.
        """
        args = arg.split()
        addr = args[0]
        assert Web3.is_address(addr), f"{addr} is not a valid address."
        if len(args) > 1:
            output_dir = args[1]
            if "/" not in output_dir:
                output_dir = os.path.join(config.output_path, output_dir)
        else:
            output_dir = None

        ret = self.peth.scan.download_json(addr, output_dir)
        if ret:
            print(f"Downloaded as {ret}")
        else:
            print("Nothing downloaded. Check `url {addr}`")

    def do_download_source(self, arg):
        """
        download_source <addr> [<output_dir>]: Download source files.
        """
        args = arg.split()
        addr = args[0]
        assert Web3.is_address(addr), f"{addr} is not a valid address."
        if len(args) > 1:
            output_dir = args[1]
            if "/" not in output_dir:
                output_dir = os.path.join(config.output_path, output_dir)
        else:
            output_dir = None

        ret = self.peth.scan.download_source(addr, output_dir)
        if ret:
            for i in ret:
                print(f"Downloaded {i}")
        else:
            print("Nothing downloaded. Check `url {addr}`")

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

    def do_verify(self, arg):
        """
        verify <addr/json file/bytecode> <addr/json file/bytecode>: Check if bytecodes match.
        """
        arg1, arg2 = arg.split()
        code1 = self._get_code(arg1)
        code2 = self._get_code(arg2)
        if code1 == code2:
            print("Exact 100% match.")
            return

        code_list1 = self._code_to_list(code1)
        code_list2 = self._code_to_list(code2)
        s = difflib.SequenceMatcher(None, code_list1, code_list2)
        similarity = s.ratio()
        print("Similarity %0.2f%%" % (similarity * 100))

        d = difflib.HtmlDiff()
        buf = d.make_file(code_list1, code_list2)
        if not os.path.exists(config.diff_path):
            os.makedirs(config.diff_path)

        path = os.path.join(config.diff_path, "bytecode_diff.html")
        open(path, "w").write(buf)
        print("Written to " + path)

    def do_url(self, arg):
        """
        url <addr> : Open blockchain explorer of the address.
        url <tx> : Open tx explorer of the tx.
        url <tx>& : Add a "&" to open blockchain explorer of the tx.
        """
        _chains_alias = {
            "eth": "eth",
            "bsc": "bsc",
            "op": "optimism",
            "arb": "arbitrum",
            "matic": "polygon",
            "avax": "avalanche",
            "ftm": "fantom",
        }

        if Web3.is_address(arg):
            url = self.peth.get_address_url(arg)
        elif len(arg) == 66 and self.peth.chain in _chains_alias:  # tx
            chain = _chains_alias[self.peth.chain]
            url = "https://phalcon.blocksec.com/explorer/tx/%s/%s" % (chain, arg)
        elif self.peth.address_url:
            url = self.peth.address_url.replace("address/", "search?f=0&q=") + arg
        else:
            print("[!] peth.address_url not set for chain %s" % self.peth.chain)
            return

        print(url)
        self.do_open('"%s"' % url)

    def do_decompile(self, addr):
        """
        decompile <addr> : Open online decompiler.
        """
        addr = addr.strip()
        if not Web3.is_address(addr):
            print(f"{addr} is not a valid address.")
            return

        if not self.peth.is_contract(addr):
            print(f"{addr} is an EOA address.")
            return

        url = self.peth.get_decompile_url(addr)
        print(url)
        self.do_open(url)

    def do_deth(self, addr):
        """
        deth <addr> : Open contract code with deth.net.
        """
        addr = addr.strip()
        if not Web3.is_address(addr):
            print("%s is not valid address." % addr)
            return

        url = self.peth.get_address_url(addr)
        if ".io/" in url:
            url = url.replace(".io/", ".deth.net/")
        elif ".com/" in url:
            url = url.replace(".com/", ".deth.net/")
        else:
            print("URL type not supported")
        print(url)
        self.do_open(url)

    def do_debank(self, addr):
        """
        debank <addr> : DeBank API to get assets balance (All chains).
        """
        addr = addr.strip().lower()
        if not Web3.is_address(addr):
            print("%s is not valid address." % addr)
            return

        print(f"https://debank.com/profile/{addr}")

        r = requests.get("https://api.debank.com/user/addr?addr=%s" % addr)
        d = r.json()
        assert d["error_code"] == 0, "DeBank addr API Error. %s" % d
        print("Total USD Value: $ %0.2f" % d["data"]["usd_value"])
        chains = d["data"]["used_chains"]

        for chain in chains:
            time.sleep(1)  # Debank API limit.
            r = requests.get(
                "https://api.debank.com/token/balance_list?user_addr=%s&chain=%s"
                % (addr, chain)
            )
            d = r.json()
            assert d["error_code"] == 0, "DeBank balance_list API Error. %s" % d
            print("-", chain.upper())
            print(
                "\t%-5s %-30s\t%-12s\t$ %-12s\t%-10s\t%-20s"
                % ("Symbol", "Name", "Balance", "USD Value", "Raw balance", "Price")
            )
            for token in d["data"]:
                name = token["name"].strip()
                symbol = token["symbol"].strip()
                decimals = token["decimals"]
                price = token["price"] if token["price"] else 0
                raw_balance = token["balance"]
                balance = token["balance"] / (10**decimals)

                if balance * price > 1:  # Only print asset more than $1.0
                    print(
                        "\t%-5s %-30s\t%-10.2f\t$ %-10.2f\t%-10s\t%-20s"
                        % (symbol, name, balance, balance * price, raw_balance, price)
                    )

    def do_price(self, arg):
        """
        price:  Print native token price.
        price <address> [<address> ...] : Print token addresses.
        """
        args = arg.split()
        chain = self.peth.chain
        if args:
            tokens = CoinPrice.get_token(chain, *args)
            for token in tokens:
                if token:
                    print(
                        "%s %s decimals %s price %s confidence %s"
                        % (
                            token["symbol"],
                            token["address"],
                            token["decimals"],
                            token["price"],
                            token["confidence"],
                        )
                    )
                else:
                    print("Unknown")
        else:
            native = CoinPrice.get_native(chain)
            if native:
                print("%s %s" % (native["symbol"], native["price"]))
            else:
                print("Unknown")
