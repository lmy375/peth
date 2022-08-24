import cmd
import json
import os
import difflib
import re

from web3 import Web3
import requests

from eth.sigs import ERC20Signatures, Signature
from eth.utils import get_4byte_sig, sha3_256
from eth.bytecode import Code
from eth.opcodes import OpCode
from core.peth import Peth
from util import diff
from util.graph import ContractRelationGraph

from . import config
from .config import chain_config, contracts_config, OUTPUT_PATH


class PethConsole(cmd.Cmd):
    """
    An interactive command console to use peth tools.
    """

    prompt = 'peth > '

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
    def scan(self):
        return self.peth.scan

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
            return False  # don't stop

    def start_console(self):
        """
        Start a peth console. Catch Ctrl+C.
        """
        print('Welcome to the peth shell. Type `help` to list commands.\n')
        while True:
            try:
                self.cmdloop()
                return
            except KeyboardInterrupt as e:
                print()  # new line.

    def single_command(self, cmd, debug=True):
        """
        Run single command. This will not catch call exception by default.
        """
        if type(cmd) is list:
            cmd = ' '.join(cmd)
        else:
            cmd = str(cmd)

        self._debug = debug
        self.onecmd(cmd)

    def __normal_str(self, v, full=False):
        if isinstance(v, bytes):
            v = v.hex()
        v = str(v).splitlines()[0]
        if not full and len(v) > 80:
            v = v[:80] + ' ...'
        return v

    def __print_json(self, data, full=False):
        if isinstance(data, list):
            i = 1
            for item in data:
                print("---- [%d] ----" % i)
                self.__print_json(item, full)
                i += 1
        elif getattr(data, "items", None):  # dict-like object.
            for k, v in data.items():
                if v:
                    v = self.__normal_str(v, full)
                print(' ', k, ":\t", v)
        else:
            print(self.__normal_str(data, full))

    ##################################################################
    # Console related commands, such as configuration commands.

    def do_debug(self, arg):
        """
        Toggle debug flag. Once on, the console will raise exceptions instead of catching them.
        """
        self._debug = not self._debug
        print("debug set to", self._debug)

    def do_chain(self, arg):
        """
        chain : Print current chain config.
        chain <chain> : Change chain.
        """

        print("Current:")
        print("Chain:", self.peth.chain)
        print("RPC:", self.peth.rpc_url)
        print("API:", self.peth.api_url)
        print("Address:", self.peth.address_url)

        if arg in chain_config:
            old_sender = self.peth.sender
            self.peth = Peth.get_or_create(arg)
            self.peth.sender = old_sender  # Keep the sender value.
            print("Changed:")
            print("Chain:", self.peth.chain)
            print("RPC:", self.peth.rpc_url)
            print("API:", self.peth.api_url)
            print("Address:", self.peth.address_url)

        else:
            print("Supported chains: %s" % ', '.join(chain_config.keys()))

    def do_config(self, arg):
        """
        config: Print current config settings.
        """
        config.print_config()
        print("Use ? exec('config.xxx = xxx') to change.")

    def do_sender(self, arg):
        """
        sender <addr> : Set default sender in eth_call.
        """
        print("Old:", self.peth.sender)
        if Web3.isAddress(arg):
            self.peth.sender = arg
            print("New:", self.peth.sender)

    ##################################################################
    # Chain-independent commands.

    def do_sha3(self, arg):
        """
        sha3 <string> : Calculate Keccak256 hash.
        """
        print(sha3_256(bytes(arg.strip(), "ascii", "ignore")).hex())


    def do_int(self, arg):
        """
        int <number> : Print number.
        """
        arg = arg.replace(',', '')
        if re.findall('[xXa-fA-f]', arg):
            value = int(arg, 16)
        else:
            value = int(arg)
        print("Value: %s" % value)
        print("Value: %e" % (value/1.0))
        print("Value/1e6: %s" % (value/1e6))
        print("Value/1e18: %s" % (value/1e18))


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

    def do_common_addresses(self, arg):
        """
        common_addresses: Print some common addresses.
        """

        print("%-40s %-10s %s" % ("Name", "Chain", "Address"))
        for name in contracts_config:
            chain, addr = contracts_config[name]
            print("%-40s %-10s %s" % (name, chain, addr))

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

    do_exit = do_bye
    do_quit = do_bye

    def do_timestamp(self, arg):
        """
        timestamp <timestamp> : Convert UNIX timestamp to local datetime.
        timestamp <seconds> : Convert seconds to hours / days.
        """
        try:
            ts = int(arg)
        except Exception as e:
            print("[!] Invalid timestamp number. %s" % e)

        if ts > 3600 * 24 * 365 * 10: 
            # If ts > 10 yrs, it's a timestamp.
            import datetime
            print(datetime.datetime.fromtimestamp(ts))
        else: 
            # else it's more likely a time interval.
            print("%d secs" % ts)
            print("= %0.1f hours" % (ts/3600))
            print("= %0.1f days" % (ts/3600/24))


    ##################################################################
    # Basic ETH commands.

    def do_eth_call(self, arg):
        """
        eth_call <to> <sig_or_name> <arg1> <arg2> ... : Call contract.
        """
        args = arg.split()
        to = args[0]
        sig_or_name = args[1]
        arg_list = args[2:]
        print(self.peth.call_contract(to, sig_or_name, arg_list))

    def do_rpc_call(self, arg):
        """
        rpc_call <method> <arg1> <arg2> ...
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
        self.__print_json(tx, True)

        print("Receipt:")
        self.__print_json(self.web3.eth.get_transaction_receipt(arg), True)

    def do_balance(self, arg):
        """
        balance <address> : Get the balance of address.
        """
        addr = self.web3.toChecksumAddress(arg)
        b = self.web3.eth.get_balance(addr)
        print('%s Wei( %0.4f Ether)' %
              (b, float(self.web3.fromWei(b, 'ether'))))

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

    def do_codesize(self, arg):
        """
        codesize <address> : Get code size of address.
        """
        addr = self.web3.toChecksumAddress(arg)
        print("Size", len(self.web3.eth.get_code(addr)))

    ##################################################################
    # Common used eth_call alias command.

    def do_get_prop(self, arg):
        """
        get_prop <contract> <name> [<type>] : Call property-like view method.
        eg:
        get_prop <contract> admin         => eth_call <contract> admin()
        get_prop <contract> admin address => eth_call <contract> admin()=>(address)
        get_prop <contract> name string => eth_call <contract> name()=>(string)
        """
        args = arg.split()
        to = args[0]
        name = args[1]
        typ = None
        if len(args) == 3:
            typ = args[2]
        print(self.peth.get_view_value(to, name, typ))


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
                value = self.peth.call_contract(arg, sig)
                print(sig, '=>', value)
        else:
            addr = args[0]
            func = args[1]
            sig = ERC20Signatures.find_by_name(func)
            assert sig, "Unknown ERC20 view function"
            value = self.peth.call_contract(addr, sig, args[2:])
            print(value)

    def do_proxy(self, args):
        """
        proxy <address> [<address>]: Print ERC1967 proxy information
        """
        for arg in args.split():
            addr = self.web3.toChecksumAddress(arg)
            impl = self.web3.eth.get_storage_at(addr, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)[12:].hex()
            admin = self.web3.eth.get_storage_at(addr, 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103)[12:].hex()
            
            if int(impl, 16) == 0:
                print(f"{addr} may be not a ERC1967 Proxy")
                print("Implementation", impl)
                print("Admin", admin)
                # Print first slots, may be used as customized proxy.
                print("Slot[0]", self.web3.eth.get_storage_at(addr, 0).hex())
                print("Slot[1]", self.web3.eth.get_storage_at(addr, 1).hex())
                print("Slot[2]", self.web3.eth.get_storage_at(addr, 2).hex())
                print("Slot[3]", self.web3.eth.get_storage_at(addr, 3).hex())
            else:
                print(f"{addr} is a ERC1967 Proxy")
                print("Implementation", impl)
                print("Admin", admin)
                print("Rollback", self.web3.eth.get_storage_at(
                    addr, 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143)[12:].hex())
                print("Beacon", self.web3.eth.get_storage_at(
                    addr, 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50)[12:].hex())
                print("Initialized", self.web3.eth.get_storage_at(
                    addr, 0x834ce84547018237034401a09067277cdcbe7bbf7d7d30f6b382b0a102b7b4a3)[12:].hex())

    def do_proxy_all(self, args):
        """
        proxy_all <address> [<address>]: Only print proxy addresses.
        """
        for arg in args.split():
            addr = self.web3.toChecksumAddress(arg)
            impl = self.web3.eth.get_storage_at(addr, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)[12:].hex()
            if int(impl, 16) != 0:
                name = self.peth.scan.get_contract_name(addr)
                if not name: name = ""
                print(f"Proxy {name} {addr} impl {impl}")

    def do_owner(self, arg):
        """
        owner <ownable-contract-address>: Print contract owner.
        """
        addr = self.web3.toChecksumAddress(arg)
        try:
            owner = self.peth.call_contract(addr, "owner()->(address)")
            print("Owner: %s" % (owner))
            self.do_name(owner)
        except Exception as e:
            print("Failed. Ensure your input is a Ownable contract address.")

    def do_gnosis(self, arg):
        """
        gnosis <gnosis-proxy-address>: Print Gnosis information.
        """
        addr = self.web3.toChecksumAddress(arg)
        try:
            threshold = self.peth.call_contract(addr, "getThreshold()->(uint)")
            users = self.peth.call_contract(addr, "getOwners()->(address[])")
            print("Policy: %s/%s" % (threshold, len(users)))
            print("Owners:")
            for u in users:
                print(" ", u)
        except Exception as e:
            print("Failed. Ensure your input is a GnosisProxy contract address.")

    def do_timelock(self, arg):
        """
        timelock <address>: Print TimelockController min delay.
        """
        addr = self.web3.toChecksumAddress(arg)
        try:
            secs = self.peth.call_contract(addr, "getMinDelay()->(uint)")
            print("Min Delay: %ds = %0.2fh" % (secs, secs/3600))
        except Exception as e:
            pass

        try:
            secs = self.peth.call_contract(addr, "MINIMUM_DELAY()->(uint)")
            print("Min Delay: %ds = %0.2fh" % (secs, secs/3600))
        except Exception as e:
            pass

        try:
            secs = self.peth.call_contract(addr, "MAXIMUM_DELAY()->(uint)")
            print("Max Delay: %ds = %0.2fh" % (secs, secs/3600))
        except Exception as e:
            pass

        try:
            secs = self.peth.call_contract(addr, "delay()->(uint)")
            print("Current Delay: %ds = %0.2fh" % (secs, secs/3600))
        except Exception as e:
            pass

        try:
            admin = self.peth.call_contract(addr, "admin()->(address)")
            print("Admin: %s" % admin)
        except Exception as e:
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
                if self.peth.chain == 'eth':
                    factory = '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'  # Uniswap Factory
                elif self.peth.chain == 'bsc':
                    factory = '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73'  # Pancake Factory

            assert factory, "Factory address not specified."
            pair_addr = self.peth.call_contract(
                factory, "getPair(address,address)->(address)", [addr1, addr2])
            assert pair_addr != "0x0000000000000000000000000000000000000000", "Token pair not found."

        print("TokenPair:", pair_addr)

        token0_name = self.peth.call_contract(addr1, "symbol()->(string)")
        token0_decimal = self.peth.call_contract(addr1, "decimals()->(uint)")

        token1_name = self.peth.call_contract(addr2, "symbol()->(string)")
        token1_decimal = self.peth.call_contract(addr2, "decimals()->(uint)")

        print("%s %s %s" % (token0_name, addr1, token0_decimal))
        print("%s %s %s" % (token1_name, addr2, token1_decimal))

        r0, r1, _ = self.peth.call_contract(
            pair_addr, "getReserves()->(uint112,uint112,uint32)")

        r0 = r0/(10**token0_decimal)
        r1 = r1/(10**token1_decimal)
        print("Reseves: %0.4f %s, %0.4f %s" %
              (r0, token0_name, r1, token1_name))

        print("Price:")
        print("1 %s = %0.4f %s" % (token0_name, r1/r0, token1_name))
        print("1 %s = %0.4f %s" % (token1_name, r0/r1, token0_name))

    def do_oracle(self, arg):
        """
        oracle <EACAggregatorProxy>[,<EACAggregatorProxy>] : Print ChainLink oracle aggregator information.
        """
        i = 1
        cnt = len(arg.split(','))
        for addr in arg.split(','):
            addr = addr.strip()
            addr = self.web3.toChecksumAddress(addr)
            try:
                if cnt > 1:
                    print('---- [%s] ----' % i)
                    i += 1

                aggr = self.peth.call_contract(addr, "aggregator()->(address)")
                print("Aggregator:", aggr)

                print("Description:", self.peth.call_contract(
                    aggr, "description()->(string)"))
                print("Owner:", self.peth.call_contract(
                    aggr, "owner()->(address)"))

                dec = self.peth.call_contract(aggr, "decimals()->(uint8)")
                print("Decimals:", dec)

                latest = self.peth.call_contract(
                    aggr, "latestAnswer()->(int256)")
                print("Latest Answer: %d (%0.2f)" % (latest, latest/(10**dec)))

                max = self.peth.call_contract(aggr, "maxAnswer()->(int192)")
                print("Max Answer: %d (%0.2f)" % (max, max/(10**dec)))

                min = self.peth.call_contract(aggr, "minAnswer()->(int192)")
                print("Min Answer: %d (%0.2f)" % (min, min/(10**dec)))

                transmitters = self.peth.call_contract(
                    aggr, "transmitters()->(address[])")
                print("%d Transmitters:" % len(transmitters))
                for addr in transmitters:
                    print(" ", addr)

            except Exception as e:
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
            if to is None:
                r = self.web3.eth.get_transaction_receipt(txid)
                contract_address = r["contractAddress"]
                print("%s creates contract %s" % (sender, contract_address))
                return
            print("%s -> %s" % (sender, to))
            if data:
                self.peth.decode_call(to, data)
        else:
            assert len(args) == 2, "Invalid args number."
            sig_or_addr = args[0]
            data = args[1]
            self.peth.decode_call(sig_or_addr, data)

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
            reverse = args[2] == 'desc'
        if len(args) >= 5:
            startblock = int(args[3])
            endblock = int(args[4])

        txs = self.peth.scan.get_txs_by_account(
            addr, startblock, endblock, count, reverse)

        if not txs:
            print("No txs.")
            return

        i = 0
        for tx in txs:
            i += 1
            print("---- [%d] %s %s ----" % (i, tx["hash"], tx["blockNumber"]))

            sender = tx["from"]
            to = tx["to"]
            data = tx["input"]
            contract = tx["contractAddress"]
            value = tx["value"]

            if Web3.isAddress(to):
                to_name = self.peth.scan.get_address_name(to)
            else:
                to_name = to

            if Web3.isAddress(contract):
                contract = self.peth.scan.get_address_name(contract)

            if contract:
                print("%s creates contract %s" % (sender, contract))
                continue

            if value:
                print("%s -> %s value %s" % (sender, to_name, value))
            else:
                print("%s -> %s" % (sender, to_name))

            if data and data != "0x":
                try:
                    self.peth.decode_call(to, data)
                except Exception as e:
                    print("Error:", e)

    def do_aml(self, arg):
        """
        aml <address> : Print funding chain related to the address.
        """
        addr = Web3.toChecksumAddress(arg)

        print("Start", addr)
        i = 1
        while True:
            if not Web3.isAddress(addr):
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

                if 'Tornado' in name: 
                    # Tornado.cash found, no sense to continue searching.
                    break
            else:
                sender = tx["from"]
                to = tx["to"]
                value = int(tx["value"])
                ethers = "%0.5f" % Web3.fromWei(value, "ether")
                print(f"[{i}] {sender} sends {to} {ethers} ETH")

            addr = sender
            i += 1

        print("End")

    ##################################################################
    # Bytecode tools.

    def do_abi4byte(self, arg):
        """
        abi4byte <addr> : disassemble the code and print all signatures.
        """
        addr = Web3.toChecksumAddress(arg)
        selectors = self.peth.get_selectors(addr)
        for selector in selectors:
            sig = '0x' + selector.hex()
            sigs = get_4byte_sig(sig)
            sigs = sigs[::-1]
            print(sig, ', '.join(sigs))

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

    ##################################################################
    # Contract source tools.

    def do_name(self, arg):
        """
        name <address> : the contract name.
        """
        if self.web3.isAddress(arg):
            addr = self.web3.toChecksumAddress(arg)
            name = self.peth.scan.get_contract_name(addr)
            if name:
                print(name)
            else:
                codesize = len(self.web3.eth.get_code(addr))
                if codesize:
                    print("Unverified contract size %s" % codesize)
                else:
                    print("EOA")
        else:
            print("Invalid address format.")

    def do_contract(self, arg):
        """
        contract <address> : print contract information (from Etherscan).
        """
        addr = self.web3.toChecksumAddress(arg)
        info = self.peth.scan.get_contract_info(arg)
        self.__print_json(info)

        abis = info["ABI"]
        try:
            abi_json = json.loads(abis)
            print(' ', "=== VIEWS ===")
            contract = self.web3.eth.contract(address=addr, abi=abi_json)

            others = []
            for func in contract.all_functions():
                sig = Signature.from_abi(func.abi)

                if sig.is_view and len(sig.inputs) == 0:
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

            print(' ', "=== OTHERS ===")
            for s in others:
                print(' ', s)

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
            
            graph = ContractRelationGraph(Web3.toChecksumAddress(root), self)
            for addr in addrs:
                addr = Web3.toChecksumAddress(addr)
                graph.visit(addr, False)
            graph.print_assets()
            print("=====================")
            print(graph.dump())
            print("=====================")
            print("Open http://relation-graph.com/#/options-tools and paste the json.")


    def __check_alias(self, alias):
        if alias in contracts_config:
            return contracts_config[alias]
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
            args = [None if i == '0' else i for i in args]
            diff.diff_pattern(*args)
            return

        if len(args) == 2:
            chain1, addr1 = self.__check_alias(args[0])
            chain2, addr2 = self.__check_alias(args[1])
            diff.diff_chain_src(chain1, addr1, chain2, addr2)
        elif len(args) == 4:
            chain1 = args[0]
            addr1 = args[1]
            chain2 = args[2]
            addr2 = args[3]
            diff.diff_chain_src(chain1, addr1, chain2, addr2)
        else:
            print('[!] Invalid args.')
            return

    def do_download_json(self, arg):
        """
        download_json <addr> [<output_dir>]: Download solc input json.
        """
        args = arg.split()
        addr = args[0]
        assert Web3.isAddress(addr), f"{addr} is not a valid address."
        if len(args) > 1:
            output_dir = args[1]
            if '/' not in output_dir:
                output_dir = os.path.join(OUTPUT_PATH, output_dir)
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
        assert Web3.isAddress(addr), f"{addr} is not a valid address."
        if len(args) > 1:
            output_dir = args[1]
            if '/' not in output_dir:
                output_dir = os.path.join(OUTPUT_PATH, output_dir)
        else:
            output_dir = None
        
        ret = self.peth.scan.download_source(addr, output_dir)
        if ret:
            for i in ret:
                print(f"Downloaded {i}")
        else:
            print("Nothing downloaded. Check `url {addr}`")

    def do_url(self, addr):
        """
        url <addr> : Open blockchain explorer of the address.
        """
        if Web3.isAddress(addr):
            url = self.peth.get_address_url(addr)
            print(url)
            self.do_open(url)
        else:
            print("%s is not a valid address." % addr)

    def do_decompile(self, addr):
        """
        decompile <addr> : Open online decompiler.
        """
        addr = addr.strip()
        if not Web3.isAddress(addr):
            print("%s is not valid address." % addr)
            return

        url = self.peth.get_decompile_url(addr)
        print(url)
        self.do_open(url)

    def do_debank(self, addr):
        """
        debank <addr> : DeBank API to get assets balance (All chains).
        """
        addr = addr.strip().lower()
        if not Web3.isAddress(addr):
            print("%s is not valid address." % addr)
            return

        r = requests.get("https://api.debank.com/user/addr?addr=%s" % addr)
        d = r.json()
        assert d["error_code"] == 0, "DeBank addr API Error. %s" % d
        chains = d["data"]["used_chains"]


        r = requests.get("https://api.debank.com/user/total_balance?addr=%s" % addr)
        d = r.json()
        assert d["error_code"] == 0, "DeBank total_balance API Error. %s" % d
        print("Total USD Value: $ %0.2f" % d["data"]["total_usd_value"])

        for chain in chains:
            r = requests.get("https://api.debank.com/token/balance_list?user_addr=%s&chain=%s" % (addr, chain))
            d = r.json()
            assert d["error_code"] == 0, "DeBank balance_list API Error. %s" % d
            print(chain)
            for token in d["data"]:
                name = token["name"]
                symbol = token["symbol"]
                decimals = token["decimals"]
                price = token["price"]
                balance = token["balance"]/(10**decimals)
                print(f"\t%-5s %-20s\t%-10.2f\t$ %-10.2f" %(symbol, name, balance, balance*price))



