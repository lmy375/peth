"""
ABI and signature related commands using Click framework.
"""

import re

import click

from peth.core.registry import command_click
from peth.eth.abi import ABIFunction
from peth.eth.utils import SelectorDatabase, convert_value


@command_click(name="4byte")
@click.argument("query")
@click.option("--online/--local", default=True, help="Query online or local database")
@click.pass_context
def fourbyte_click(ctx, query, online):
    """
    Query function signatures by selector or text.

    \b
    Examples:
        4byte 0x095ea7b3              # Query by selector
        4byte transfer                # Search for signatures containing "transfer"
        4byte approve --local         # Search in local database only
    """

    try:
        db = SelectorDatabase.get()
    except Exception as e:
        click.echo(f"Error loading selector database: {e}", err=True)
        return

    if re.match("^[0-9A-Fa-fXx]*$", query):  # selector
        try:
            sigs = db.get_sig_from_selector(query, False, online)
            if sigs:
                click.echo("\n".join(sigs))
            else:
                if online:
                    click.echo(
                        "Selector not found in https://openchain.xyz/signatures."
                    )
                else:
                    click.echo("Selector not found in local database.")
        except Exception as e:
            click.echo(f"Error querying selector: {e}", err=True)
    else:
        try:
            ret = db.get_sig_from_text(query)
            full_match = None
            if ret:
                for selector, sigs in ret:
                    if query in sigs:
                        full_match = (selector, ", ".join(sigs))
                    click.echo(f"0x{selector} {', '.join(sigs)}")

            click.echo(f"{len(ret)} item(s) found in 4byte.json.")
            if full_match:
                click.echo(f"Full match: 0x{full_match[0]} {full_match[1]}")
        except Exception as e:
            click.echo(f"Error searching text: {e}", err=True)


@command_click(name="abi_encode")
@click.argument("signature")
@click.argument("args", nargs=-1)
@click.option("--selector-only", is_flag=True, help="Output only the function selector")
@click.pass_context
def abi_encode_click(ctx, signature, args, selector_only):
    """
    Encode function call data with ABI.

    \b
    Examples:
        abi_encode "transfer(address,uint256)" 0xEEE... 1000
        abi_encode "approve(address,uint256)" 0xEEE... 1000
        abi_encode "transfer(address,uint256)" --selector-only
    """
    f = ABIFunction(signature)

    if selector_only or not args:
        click.echo(f.selector.hex())
        return

    # Convert arguments
    converted_args = list(map(convert_value, args))
    encoded = f.encode_input(converted_args)
    click.echo(encoded.hex())


@command_click(name="abi_decode")
@click.argument("hexdata")
@click.argument("signature", required=False)
@click.option(
    "--guess-types", is_flag=True, help="Guess types if signature not provided"
)
@click.pass_context
def abi_decode_click(ctx, hexdata, signature, guess_types):
    """
    Decode ABI-encoded calldata.

    \b
    Examples:
        abi_decode 0x095ea7b3000...
        abi_decode 0x095ea7b3000... "approve(address,uint256)"
        abi_decode 0x095ea7b3000... --guess-types
    """

    # Validate hex data
    if not re.match("^[0-9A-Fa-fXx]+$", hexdata):
        click.echo(f"Invalid hex data: {hexdata}", err=True)
        return

    # Use console's helper method
    ctx.obj._print_decoded_calldata(hexdata, sig=signature)
