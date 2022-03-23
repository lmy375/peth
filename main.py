import json
from argparse import ArgumentParser

from core.config import chain_config
from core.peth import Peth
from core.console import PethConsole

def get_args():
    parser = ArgumentParser(
        prog='peth',
        description="A python Ethereum utilities command-line tool."
    )

    parser.add_argument(
        "-c",
        "--chain",
        choices=list(chain_config.keys()),
        default='eth',
        help="Chain of the contract.",
    )

    parser.add_argument(
        "-r",
        "--rpc-call",
        metavar="ARG",
        nargs="+",
        help="Ethereum RPC call: method arg1 arg2 [...]",
    )

    parser.add_argument(
        "--rpc-call-raw",
        metavar="ARG",
        nargs=2,
        help="Ethereum RPC call: method arguments",
    )

    parser.add_argument(
        "-e",
        "--eth-call", 
        metavar="ARG",
        nargs="+",
        help="Ethereum RPC eth_call: signature arg1 [...]"
    )

    parser.add_argument(
        "--sender",
        default="0x0000000000000000000000000000000000000000",
        help="Use as `from` in eth_call transactions."
    )

    parser.add_argument(
        "--to",
        help="Use as `to` in eth_call transactions."
    )

    parser.add_argument(
        "--rpc-url",
        help="RPC endpoint.",
    )
    parser.add_argument(
        "--scan-url",
        help="Etherscan like blockchain explorer API URL.",
    )
    parser.add_argument(
        "--address-url",
        help="Etherscan like blockchain explorer address URL.",
    )

    parser.add_argument(
        "--console",
        action="store_true",
        help="Start peth console.",
    )

    parser.add_argument(
        "--cmd",
        nargs="+",
        help="Execute one command in peth console.",
    )

    parser.add_argument(
        "--graph",
        action="store_true",
        help="Generate contract graph.",
    )

    args = parser.parse_args()
    return args

    
def main():
    global peth

    args = get_args()

    if args.rpc_url:
        peth = Peth(args.rpc_url, args.api_url, args.address_url)
    else:
        peth = Peth.get_or_create(args.chain)

    if args.rpc_call_raw:
        method = args.rpc_call_raw[0]
        arg_list = json.loads(args.rpc_call_raw[1])
        print(peth.rpc_call_raw(method, arg_list))
    elif args.rpc_call:
        method = args.rpc_call[0]
        arg_list = args.rpc_call[1:]
        print(peth.rpc_call(method, arg_list))
    elif args.eth_call:
        sender = args.sender
        to = args.to
        sig_or_name = args.eth_call[0]
        arg_list = args.eth_call[1:]
        print(peth.eth_call(to, sig_or_name, arg_list, sender))
    elif args.graph:
        addr = args.to
        peth.print_contract_graph(addr)

    c = PethConsole(peth)
    if args.console:
        c.start_console()
    elif args.cmd:
        c.single_command(args.cmd)

if __name__ == "__main__":
    main()