"""
Utility commands using Click framework.
This file demonstrates how to convert commands to use Click for better parameter handling.
"""

import re
import time as time_module
from datetime import datetime

import click
from eth_account import Account
from hexbytes import HexBytes

from peth.core.config import config
from peth.core.registry import command_click
from peth.eth.utils import CoinPrice
from peth.eth.utils import keccak256 as keccak256_func


@command_click(name="keccak256")
@click.argument("text")
@click.option("--encoding", default="utf-8", help="Text encoding (default: utf-8)")
@click.pass_context
def keccak256_click(ctx, text, encoding):
    """
    Calculate Keccak256 hash.

    Examples:
        keccak256 "hello world"
        keccak256 "hello world" --encoding ascii
    """
    result = keccak256_func(bytes(text.strip(), encoding)).hex()
    click.echo(result)


@command_click(name="int")
@click.argument("value")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["standard", "hex", "address", "uint256", "all"]),
    default="all",
    help="Output format",
)
@click.option(
    "--unit",
    "-u",
    type=click.Choice(["wei", "gwei", "ether", "usdt", "btc"]),
    help="Show value in specific unit",
)
@click.pass_context
def int_command_click(ctx, value, format, unit):
    """
    Print number in various formats.

    Examples:
        int 12345
        int 0x1234 --format hex
        int 1000000 --unit ether
        int 1e18 --format standard
    """
    # Remove commas
    value = value.replace(",", "")

    # Parse the value
    if "e" in value.lower():
        num_value = int(float(value))
    elif re.findall("[xXa-fA-f]", value):
        num_value = int(value, 16)
    else:
        num_value = int(value)

    if unit:
        # Show specific unit conversion
        if unit == "wei":
            click.echo(f"{num_value} Wei")
        elif unit == "gwei":
            click.echo(f"{num_value / 1e9} Gwei")
        elif unit == "ether":
            click.echo(f"{num_value / 1e18} Ether")
        elif unit == "usdt":
            click.echo(f"{num_value / 1e6} USDT")
        elif unit == "btc":
            click.echo(f"{num_value / 1e8} BTC")
    elif format == "standard":
        click.echo(f"Value: {num_value}")
        click.echo(f"Value: {num_value:e}")
    elif format == "hex":
        click.echo(f"Hex: {num_value:#x}")
    elif format == "address":
        click.echo(f"Hex(Address): 0x{num_value:040x}")
    elif format == "uint256":
        click.echo(f"Hex(Uint256): {num_value:064x}")
    else:  # all
        click.echo(f"Value: {num_value}")
        click.echo(f"Value: {num_value:e}")
        click.echo(f"Value/1e6  (USDT): {num_value / 1e6}")
        click.echo(f"Value/1e8  (BTC): {num_value / 1e8}")
        click.echo(f"Value/1e9  (GWei): {num_value / 1e9}")
        click.echo(f"Value/1e18 (Ether): {num_value / 1e18}")
        click.echo(f"Hex: {num_value:#x}")
        click.echo(f"Hex(Address): 0x{num_value:040x}")
        click.echo(f"Hex(Uint256): {num_value:064x}")


@command_click(name="time")
@click.argument("timestamp", required=False, type=int)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["timestamp", "interval", "auto"]),
    default="auto",
    help="Output format",
)
@click.pass_context
def time_command_click(ctx, timestamp, format):
    """
    Convert UNIX timestamp to datetime or seconds to time intervals.

    Examples:
        time                    # Show current timestamp
        time 1234567890         # Convert timestamp to datetime
        time 3600 --format interval  # Show as time interval
    """
    if not timestamp:
        click.echo(f"Current: {int(time_module.time())}")
        return

    if format == "timestamp" or (format == "auto" and timestamp > 3600 * 24 * 365 * 10):
        # Show as timestamp
        dt = datetime.fromtimestamp(timestamp)
        click.echo(str(dt))
    else:
        # Show as interval
        click.echo(f"{timestamp} secs")
        click.echo(f"= {timestamp / 3600:.1f} hours")
        click.echo(f"= {timestamp / 3600 / 24:.1f} days")


@command_click(name="addresses")
@click.option("--chain", help="Filter by chain")
@click.option("--search", help="Search in name or address")
@click.pass_context
def addresses_click(ctx, chain, search):
    """
    Print common contract addresses.

    Examples:
        addresses
        addresses --chain eth
        addresses --search uniswap
    """
    click.echo(f"{'Name':<40} {'Chain':<10} {'Address'}")
    for name in config.contracts:
        contract_chain, addr = config.contracts[name]

        # Apply filters
        if chain and contract_chain != chain:
            continue
        if (
            search
            and search.lower() not in name.lower()
            and search.lower() not in addr.lower()
        ):
            continue

        click.echo(f"{name:<40} {contract_chain:<10} {addr}")


@command_click(name="price")
@click.argument("addresses", nargs=-1)
@click.option("--native", is_flag=True, help="Show native token price")
@click.pass_context
def price_click(ctx, addresses, native):
    """
    Get token prices.

    Examples:
        price --native          # Show native token price
        price 0x123... 0x456... # Show prices for specific tokens
    """
    chain = ctx.obj.peth.chain

    if native or not addresses:
        # Show native token price
        native_info = CoinPrice.get_native(chain)
        if native_info:
            click.echo(f"{native_info['symbol']} {native_info['price']}")
        else:
            click.echo("Unknown")

    if addresses:
        # Show token prices
        tokens = CoinPrice.get_token(chain, *addresses)
        for token in tokens:
            if token:
                click.echo(
                    f"{token['symbol']} {token['address']} "
                    f"decimals {token['decimals']} "
                    f"price {token['price']} "
                    f"confidence {token['confidence']}"
                )
            else:
                click.echo("Unknown")


@command_click(name="brain")
@click.argument("password")
@click.option(
    "--iterations",
    "-i",
    default=10000000,
    type=int,
    help="Number of hash iterations (default: 10,000,000)",
)
@click.option("--show-progress", is_flag=True, help="Show progress bar")
@click.pass_context
def brain_wallet_click(ctx, password, iterations, show_progress):
    """
    Generate brain wallet from password.

    Examples:
        brain "my secret password"
        brain "my secret password" --iterations 1000000
        brain "my secret password" --show-progress
    """
    click.echo(f"Key: {repr(password)}")
    click.echo(f"Count: {iterations}")

    password_bytes = password.encode("utf-8")

    if show_progress:
        with click.progressbar(range(iterations), label="Hashing") as bar:
            for i in bar:
                password_bytes = keccak256_func(password_bytes)
    else:
        for i in range(iterations):
            if (i % 100000) == 0:
                click.echo(f"    {100 * i / iterations:.0f} %\r", nl=False)
            password_bytes = keccak256_func(password_bytes)

    pk = HexBytes(password_bytes).hex()

    click.echo(f"\nPrivate Key: {pk}")
    click.echo(f"Address: {Account.from_key(pk).address}")


@command_click(name="portfolio")
@click.argument("address")
@click.option(
    "--sort",
    type=click.Choice(["name", "symbol", "value", "balance"]),
    default="value",
    help="Sort by field",
)
@click.option("--min-value", type=float, default=0, help="Minimum USD value to show")
@click.pass_context
def portfolio_click(ctx, address, sort, min_value):
    """
    Print token portfolio for an address.

    Examples:
        portfolio 0x123...
        portfolio 0x123... --sort value
        portfolio 0x123... --min-value 100
    """
    addr = ctx.obj._parse_args(address, "address")

    portfolio = ctx.obj.peth.get_portfolio([addr])
    infos = portfolio.get(addr.lower(), [])

    # Filter by min value
    if min_value > 0:
        infos = [asset for asset in infos if asset["usd"] >= min_value]

    # Sort
    if sort == "name":
        infos.sort(key=lambda x: x["info"]["name"])
    elif sort == "symbol":
        infos.sort(key=lambda x: x["info"]["symbol"])
    elif sort == "balance":
        infos.sort(key=lambda x: x["balance"], reverse=True)
    else:  # value
        infos.sort(key=lambda x: x["usd"], reverse=True)

    total = sum(asset["usd"] for asset in infos)

    click.echo(f"Total: ${total:,.2f}")
    click.echo(
        f"{'Name':<30}\t{'Symbol':<10}\t{'Address':<45}\t"
        f"{'Price':<10}\t{'Balance':<20}\t{'USD':<20}"
    )

    for asset in infos:
        click.echo(
            f"{asset['info']['name']:<30}\t"
            f"{asset['info']['symbol']:<10}\t"
            f"{asset['info']['address']:<45}\t"
            f"{asset['info']['price']:<10}\t"
            f"{asset['balance']:<20}\t"
            f"{asset['usd']:<20}"
        )


@command_click(name="tokens")
@click.argument("search", required=False)
@click.pass_context
def tokens_click(ctx, search):
    """
    Print tokens or search for specific tokens.

    Examples:
        tokens                  # List all tokens
        tokens usdt            # Search for tokens containing 'usdt'
    """
    tokens = config.tokens[ctx.obj.peth.chain]
    search_text = search or ""

    click.echo(
        f"{'Name':<30} {'Symbol':<10} {'Address':<45} " f"{'Decimals':>8} {'Price':>15}"
    )
    for token in tokens:
        line = (
            f"{token['name']:<30} {token['symbol']:<10} "
            f"{token['address']:<45} {token['decimals']:>8} "
            f"{token['price']:>15}"
        )
        if search_text.lower() in line.lower():
            click.echo(line)


@command_click(name="aes")
@click.argument("operation", type=click.Choice(["enc", "dec"]))
@click.argument("text")
@click.argument("password")
@click.pass_context
def aes_click(ctx, operation, text, password):
    """
    Encrypt or decrypt text with AES.

    Examples:
        aes enc "plain text" mypassword
        aes dec 1a2b3c4d5e6f mypassword

    NOTE: IV used as MD5 of password, which is not so safe.
    """
    import hashlib

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    key = pad(bytes(password, "utf-8"), 16)
    iv = hashlib.md5(bytes(password, "utf-8")).digest()

    if operation == "enc":
        plain = pad(bytes(text, "utf-8"), 16)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)
        secret = aes.encrypt(plain)
        click.echo(secret.hex())
    else:  # dec
        try:
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
            secret = bytes.fromhex(text)
            plain = unpad(aes.decrypt(secret), 16)
            click.echo(plain.decode("utf-8"))
        except Exception as e:
            click.echo(f"[!] {e} (Password may be wrong)", err=True)
