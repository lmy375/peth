import json
from argparse import ArgumentParser

from config import config
from peth import Peth
from console import PethConsole

def get_args():
    parser = ArgumentParser(
        prog='peth',
        description="A python Ethereum utilities command-line tool."
    )

    parser.add_argument(
        "-c",
        "--chain",
        choices=list(config.keys()),
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
        help="Etherscan like blockchain explorer API url.",
    )

    parser.add_argument(
        "--console",
        action="store_true",
        help="Start peth console.",
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
        peth = Peth(args.rpc_url, args.scan_url)
    else:
        peth = Peth(*config[args.chain])

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
        print(peth.eth_call(sender, to, sig_or_name, arg_list))
    elif args.graph:
        addr = args.to
        peth.print_contract_graph(addr)

    if args.console:
        c = PethConsole(peth)
        c.cmdloop()

    # 
    
    # addr = Web3.toChecksumAddress(args.address)

    # args.func(args)

    # python peth.py 
    # rpc method args
    # call sig args



    # balance address
    # nonce address
    # storage address

    # address address
    # erc20 address
    # proxy address
    # 



if __name__ == "__main__":
    main()