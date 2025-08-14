"""
Bytecode and disassembly related commands using Click framework.
"""

import difflib
import os

import click
from web3 import Web3

from peth.core.config import config
from peth.core.registry import command_click
from peth.eth.abi import ABIFunction
from peth.eth.bytecode import Code
from peth.eth.utils import guess_single_calldata, selector_to_sigs


@command_click(name="abi4byte")
@click.argument("address")
@click.pass_context
def abi4byte_click(ctx, address):
    """
    Disassemble the code and print all function signatures.

    Examples:
        abi4byte 0x123...                  # Get all function signatures from contract
    """
    console = ctx.obj
    addr = Web3.to_checksum_address(address)
    selectors = console.peth.get_selectors(addr)

    for selector in selectors:
        sig = "0x" + selector.hex()
        sigs = selector_to_sigs(sig)
        sigs = sigs[::-1]
        typ = ""
        value = ""

        if sigs:
            func_sig = sigs[0]
            if len(ABIFunction(func_sig).inputs) == 0:
                value = console.peth.call_contract(addr, func_sig, silent=True)
                if value is None:
                    value = ""
                else:
                    typ, value = guess_single_calldata(value)

        click.echo(f"{sig} {', '.join(sigs):<50} \t{typ} {value}")


@command_click(name="disasm")
@click.argument("address")
@click.pass_context
def disasm_click(ctx, address):
    """
    Get assembly code of an address.

    Examples:
        disasm 0x123...                    # Disassemble bytecode at address
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)
    code = console.web3.eth.get_code(addr)

    if not code:
        click.echo(f"No code found at address {addr}", err=True)
        return

    click.echo(Code.disasm(code))


@command_click(name="diffasm")
@click.argument("chain1")
@click.argument("addr1")
@click.argument("chain2")
@click.argument("addr2")
@click.option("--output", "-o", help="Output filename (without extension)")
@click.option(
    "--open", "open_file", is_flag=True, help="Open the diff file after creation"
)
@click.pass_context
def diffasm_click(ctx, chain1, addr1, chain2, addr2, output, open_file):
    """
    Compare bytecode between two addresses (can be on different chains).

    Examples:
        diffasm eth 0x123... bsc 0x456...  # Compare bytecode across chains
        diffasm eth 0x123... eth 0x456...  # Compare bytecode on same chain
        diffasm eth 0x123... bsc 0x456... --open  # Open diff in browser
    """
    console = ctx.obj

    # Get assembly lines for both addresses
    asm1 = console._get_asm_lines(chain1, addr1)
    asm2 = console._get_asm_lines(chain2, addr2)

    # Calculate similarity
    s = difflib.SequenceMatcher(None, asm1, asm2)
    similarity = s.ratio()

    # Generate HTML diff
    d = difflib.HtmlDiff()
    buf = d.make_file(
        asm1, asm2, fromdesc=f"{chain1}:{addr1}", todesc=f"{chain2}:{addr2}"
    )

    # Prepare output filename
    if output:
        output_filename = output
    else:
        output_filename = f"{chain1}_{addr1[:8]}_{chain2}_{addr2[:8]}_{similarity:.2f}"

    # Ensure diff directory exists
    if not os.path.isdir(config.diff_path):
        os.makedirs(config.diff_path)

    # Write the file
    full_path = os.path.join(config.diff_path, output_filename + ".html")
    with open(full_path, "w") as f:
        f.write(buf)

    click.echo(f"Written to {full_path}")
    click.echo(f"Similarity: {similarity:.2%}")

    # Open the file if requested
    if open_file:
        console.open_cmd(full_path)
