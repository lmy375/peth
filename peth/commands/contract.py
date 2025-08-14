"""
Contract and source code related commands using Click framework.
"""

import difflib
import json
import os

import click
from web3 import Web3

from peth.core.config import config
from peth.core.registry import command_click
from peth.eth.sigs import Signature
from peth.util import diff as diff_module
from peth.util.graph import ContractRelationGraph


@command_click(name="name")
@click.argument("address")
@click.pass_context
def name_click(ctx, address):
    """
    Get the contract name.

    Examples:
        name 0x123...                       # Get contract name from Etherscan
    """
    console = ctx.obj
    if console.web3.is_address(address):
        click.echo(console._get_full_name(address))
    else:
        click.echo("Invalid address format.", err=True)


@command_click(name="contract")
@click.argument("address")
@click.option("--json", "output_json", is_flag=True, help="Output raw JSON")
@click.pass_context
def contract_click(ctx, address, output_json):
    """
    Print contract information from Etherscan.

    Examples:
        contract 0x123...                   # Get contract info
        contract 0x123... --json            # Output raw JSON
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)
    info = console.peth.scan.get_contract_info(address)

    if info is None:
        click.echo("Contract not verified. Running abi4byte...")
        ctx.invoke(abi4byte_click, address=addr)
        return

    if output_json:
        click.echo(json.dumps(info, indent=2))
        return

    console._print_json(info)

    abis = info["ABI"]
    try:
        abi_json = json.loads(abis)
        click.echo("  === CALLABLE FUNCTIONS ===")
        contract = console.web3.eth.contract(address=addr, abi=abi_json)

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
                    click.echo(f"  [*] Error calling {sig}: {e}")
                    continue
                click.echo(f"  {sig} => {ret}")
            else:
                others.append(sig)

        click.echo("  === OTHER FUNCTIONS ===")
        for s in others:
            click.echo(f"  {s}")

    except Exception as e:
        click.echo(f"Error parsing ABI: {e}", err=True)
        click.echo(abis)


@command_click(name="graph")
@click.argument("addresses", nargs=-1, required=True)
@click.option("--output", "-o", help="Output JSON file path")
@click.pass_context
def graph_click(ctx, addresses, output):
    """
    Print contract relation graph.

    Examples:
        graph 0x123...                      # Graph single contract
        graph 0x123... 0x456... 0x789...   # Graph multiple contracts
        graph 0x123... --output graph.json  # Save to file
    """
    console = ctx.obj

    root = Web3.to_checksum_address(addresses[0])
    graph = ContractRelationGraph(root, console)

    for addr in addresses:
        addr = Web3.to_checksum_address(addr)
        graph.visit(addr, False)

    graph.print_assets()
    click.echo("=====================")
    graph_json = graph.dump()
    click.echo(graph_json)
    click.echo("=====================")

    if output:
        with open(output, "w") as f:
            f.write(graph_json)
        click.echo(f"Graph saved to {output}")

    click.echo("Open http://relation-graph.com/#/options-tools and paste the JSON.")


@command_click(name="diff")
@click.argument("args", nargs=-1, required=True)
@click.pass_context
def diff_click(ctx, args):
    """
    Compare contract source code across chains.

    Examples:
        diff addr1/alias addr2/alias
        diff chain1 addr1 chain2 addr2

        # Pattern-based diff:
        diff uni bsc factory pair router
        diff sushi eth masterchef_addr
        diff comp eth comptroller_impl
        diff ctoken eth cERC20_impl

        # Use 0 as placeholder for unknown addresses:
        diff uni bsc 0 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0 0
    """
    console = ctx.obj

    if args[0] in diff_module.PATTERNS:
        # Pattern-based diff
        args_list = [None if i == "0" else i for i in args]
        diff_module.diff_pattern(*args_list)
        return

    if len(args) == 2:
        # Two addresses/aliases
        chain1, addr1 = console._check_alias(args[0])
        chain2, addr2 = console._check_alias(args[1])
        diff_module.diff_chain_src(chain1, addr1, chain2, addr2)
    elif len(args) == 4:
        # Four arguments: chain1 addr1 chain2 addr2
        chain1, addr1, chain2, addr2 = args
        diff_module.diff_chain_src(chain1, addr1, chain2, addr2)
    else:
        click.echo("Invalid arguments. See 'help diff' for usage.", err=True)


@command_click(name="download_json")
@click.argument("address")
@click.argument("output_dir", required=False)
@click.pass_context
def download_json_click(ctx, address, output_dir):
    """
    Download Solidity compiler input JSON.

    Examples:
        download_json 0x123...              # Download to default location
        download_json 0x123... myproject    # Download to specific directory
    """
    console = ctx.obj

    if not Web3.is_address(address):
        click.echo(f"{address} is not a valid address.", err=True)
        return

    if output_dir and "/" not in output_dir:
        output_dir = os.path.join(config.output_path, output_dir)

    ret = console.peth.scan.download_json(address, output_dir)
    if ret:
        click.echo(f"Downloaded as {ret}")
    else:
        click.echo(f"Nothing downloaded. Check 'url {address}'")


@command_click(name="download_source")
@click.argument("address")
@click.argument("output_dir", required=False)
@click.pass_context
def download_source_click(ctx, address, output_dir):
    """
    Download contract source files.

    Examples:
        download_source 0x123...            # Download to default location
        download_source 0x123... myproject  # Download to specific directory
    """
    console = ctx.obj

    if not Web3.is_address(address):
        click.echo(f"{address} is not a valid address.", err=True)
        return

    if output_dir and "/" not in output_dir:
        output_dir = os.path.join(config.output_path, output_dir)

    ret = console.peth.scan.download_source(address, output_dir)
    if ret:
        for file_path in ret:
            click.echo(f"Downloaded {file_path}")
    else:
        click.echo(f"Nothing downloaded. Check 'url {address}'")


@command_click(name="verify")
@click.argument("source1")
@click.argument("source2")
@click.option("--open", "open_diff", is_flag=True, help="Open diff file after creation")
@click.pass_context
def verify_click(ctx, source1, source2, open_diff):
    """
    Check if bytecodes match between addresses/files.

    Examples:
        verify 0x123... 0x456...            # Compare two addresses
        verify contract.json 0x123...       # Compare JSON file with address
        verify 0x606060... 0x606060...      # Compare raw bytecodes
    """
    console = ctx.obj

    code1 = console._get_code(source1)
    code2 = console._get_code(source2)

    if code1 == code2:
        click.echo("Exact 100% match.")
        return

    code_list1 = console._code_to_list(code1)
    code_list2 = console._code_to_list(code2)
    s = difflib.SequenceMatcher(None, code_list1, code_list2)
    similarity = s.ratio()
    click.echo(f"Similarity {similarity:.2%}")

    d = difflib.HtmlDiff()
    buf = d.make_file(
        code_list1, code_list2, fromdesc=source1[:20], todesc=source2[:20]
    )

    if not os.path.exists(config.diff_path):
        os.makedirs(config.diff_path)

    path = os.path.join(config.diff_path, "bytecode_diff.html")
    with open(path, "w") as f:
        f.write(buf)
    click.echo(f"Written to {path}")

    if open_diff:
        console.open_cmd(path)


@command_click(name="url")
@click.argument("target")
@click.pass_context
def url_click(ctx, target):
    """
    Open blockchain explorer for address or transaction.

    Examples:
        url 0x123...                        # Open address in explorer
        url 0x123...abc                     # Open transaction in explorer
    """
    console = ctx.obj

    _chains_alias = {
        "eth": "eth",
        "bsc": "bsc",
        "op": "optimism",
        "arb": "arbitrum",
        "matic": "polygon",
        "avax": "avalanche",
        "ftm": "fantom",
    }

    if Web3.is_address(target):
        url = console.peth.get_address_url(target)
    elif len(target) == 66 and console.peth.chain in _chains_alias:  # tx hash
        chain = _chains_alias[console.peth.chain]
        url = f"https://phalcon.blocksec.com/explorer/tx/{chain}/{target}"
    elif console.peth.address_url:
        url = console.peth.address_url.replace("address/", "search?f=0&q=") + target
    else:
        click.echo(f"peth.address_url not set for chain {console.peth.chain}", err=True)
        return

    click.echo(url)
    console.open_cmd(f'"{url}"')


@command_click(name="decompile")
@click.argument("address")
@click.pass_context
def decompile_click(ctx, address):
    """
    Open online decompiler for contract.

    Examples:
        decompile 0x123...                  # Open in Dedaub decompiler
    """
    console = ctx.obj

    if not Web3.is_address(address):
        click.echo(f"{address} is not a valid address.", err=True)
        return

    if not console.peth.is_contract(address):
        click.echo(f"{address} is an EOA address.", err=True)
        return

    url = console.peth.get_decompile_url(address)
    click.echo(url)
    console.open_cmd(url)


@command_click(name="deth")
@click.argument("address")
@click.pass_context
def deth_click(ctx, address):
    """
    Open contract code with deth.net.

    Examples:
        deth 0x123...                       # View contract in deth.net
    """
    console = ctx.obj

    if not Web3.is_address(address):
        click.echo(f"{address} is not a valid address.", err=True)
        return

    url = console.peth.get_address_url(address)
    if ".io/" in url:
        url = url.replace(".io/", ".deth.net/")
    elif ".com/" in url:
        url = url.replace(".com/", ".deth.net/")
    else:
        click.echo("URL type not supported", err=True)
        return

    click.echo(url)
    console.open_cmd(url)


@command_click(name="debank")
@click.argument("address")
@click.pass_context
def debank_click(ctx, address):
    """
    Open DeBank profile to view assets across all chains.

    Examples:
        debank 0x123...                     # View address on DeBank
    """
    console = ctx.obj

    address = address.strip().lower()
    if not Web3.is_address(address):
        click.echo(f"{address} is not a valid address.", err=True)
        return

    url = f"https://debank.com/profile/{address}"
    click.echo(url)
    console.open_cmd(url)


# Import reference to abi4byte command from bytecode module
from .bytecode import abi4byte_click
