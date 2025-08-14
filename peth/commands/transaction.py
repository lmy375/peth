"""
Transaction related commands using Click framework.
"""

import codecs

import click
from hexbytes import HexBytes
from web3 import Web3

from peth.core.registry import command_click
from peth.core.tracer import GethTracer, TxTrace
from peth.eth.evm import VM, Chain, ForkChain, Transaction


@command_click(name="tx")
@click.argument("args", nargs=-1, required=True)
@click.pass_context
def tx_click(ctx, args):
    """
    Decode transaction or call data.

    Examples:
        tx 0x123...abc                      # Decode transaction by hash
        tx 0x123... 0x456...                # Decode calldata for address
        tx transfer(address,uint256) 0x...  # Decode calldata with signature
    """
    console = ctx.obj

    if len(args) == 1:
        # Transaction ID
        txid = args[0]
        info = console.web3.eth.get_transaction(txid)
        sender = info["from"]
        to = info["to"]
        data = info["input"]
        r = console.web3.eth.get_transaction_receipt(txid)

        if to is None:
            contract_address = r["contractAddress"]
            click.echo(f"{sender} creates contract {contract_address}")
        else:
            click.echo(f"From: {sender}\nTo: {to}")
            if data:
                console._print_decoded_calldata(data, to)

        if r.status == 0:
            click.echo("Tx reverted.")
            return

        # Process ERC20 transfers
        erc20_trans = []
        for item in r.logs:
            address_names = {sender: "sender", to: "to"}

            # Transfer event
            if (
                len(item.topics) == 3
                and item.topics[0].hex()
                == "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            ):

                src = console.web3.to_checksum_address(item.topics[1][-20:])
                src = address_names.get(src, src)
                dst = console.web3.to_checksum_address(item.topics[2][-20:])
                dst = address_names.get(dst, dst)

                amount = console.web3.to_int(hexstr=item.data.hex())
                token = item.address
                symbol = console.peth.call_contract(
                    token, "symbol()->(string)", silent=True
                )
                if symbol is None:
                    symbol = "Unknown"
                token = f"{symbol}({token})"
                msg = f"{token} {src}->{dst} {amount}"
                erc20_trans.append(msg)

        if erc20_trans:
            click.echo("ERC20 Transfers:")
            for msg in erc20_trans:
                click.echo(f"  {msg}")

    elif len(args) == 2:
        # Address/signature and data
        sig_or_addr = args[0]
        data = args[1]

        if Web3.is_address(sig_or_addr):
            console._print_decoded_calldata(data, sig_or_addr, None)
        else:
            console._print_decoded_calldata(data, None, sig_or_addr)
    else:
        click.echo("Invalid number of arguments. See 'help tx'", err=True)


@command_click(name="idm")
@click.argument("address")
@click.argument("count", type=int, default=10, required=False)
@click.argument(
    "order", type=click.Choice(["asc", "desc"]), default="asc", required=False
)
@click.argument("startblock", type=int, required=False)
@click.argument("endblock", type=int, required=False)
@click.pass_context
def idm_click(ctx, address, count, order, startblock, endblock):
    """
    Print IDM (Internal Data Messages) for an address.

    Examples:
        idm 0x123...                        # First 10 IDM messages
        idm 0x123... 20                     # First 20 IDM messages
        idm 0x123... 20 desc                # Last 20 IDM messages
        idm 0x123... 100 asc 1000000 2000000  # Messages between blocks
    """
    console = ctx.obj
    reverse = order == "desc"

    txs = console.peth.scan.get_txs_by_account(
        address, startblock, endblock, count, reverse
    )

    if not txs:
        click.echo("No transactions found.")
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

        if sender == address:
            sender = "Hacker"
        if to == address:
            to = "Hacker"

        i += 1
        click.echo(f"---- [{i}] {sender} to {to} ({value/1e18:.4f} ETH) ----")

        try:
            msg = codecs.decode(data, "hex").decode("utf-8")
            click.echo(msg)
        except Exception:
            click.echo("Decode failed.")


@command_click(name="txs")
@click.argument("address")
@click.argument("count", type=int, default=10, required=False)
@click.argument(
    "order", type=click.Choice(["asc", "desc"]), default="asc", required=False
)
@click.argument("startblock", type=int, required=False)
@click.argument("endblock", type=int, required=False)
@click.option("--full", is_flag=True, help="Show full transaction details")
@click.pass_context
def txs_click(ctx, address, count, order, startblock, endblock, full):
    """
    Print transactions for an address.

    Examples:
        txs 0x123...                        # First 10 transactions
        txs 0x123... 20                     # First 20 transactions
        txs 0x123... 20 desc                # Last 20 transactions
        txs 0x123... 100 asc 1000000 2000000  # Txs between blocks
        txs 0x123... --full                 # Show full details
    """
    console = ctx.obj
    reverse = order == "desc"

    txs = console.peth.scan.get_txs_by_account(
        address, startblock, endblock, count, reverse
    )

    if not txs:
        click.echo("No transactions found.")
        return

    for i, tx in enumerate(txs, 1):
        click.echo(f"---- [{i}] {tx['hash']} Block: {tx['blockNumber']} ----")

        sender = tx["from"]
        to = tx["to"]
        data = HexBytes(tx["input"])
        contract = tx["contractAddress"]
        value = tx["value"]

        if Web3.is_address(to):
            to_name = console.peth.scan.get_address_name(to)
        else:
            to_name = to

        if Web3.is_address(contract):
            contract = console.peth.scan.get_address_name(contract)

        if contract:
            click.echo(f"{sender} creates contract {contract}")
            continue

        if value:
            click.echo(f"{sender} -> {to_name} value {value}")
        else:
            click.echo(f"{sender} -> {to_name}")

        if len(data) > 4 and full:
            try:
                console._print_decoded_calldata(data, to)
            except Exception as e:
                click.echo(f"Error: {e}")


@command_click(name="aml")
@click.argument("address")
@click.option("--max-depth", "-d", type=int, default=100, help="Maximum depth to trace")
@click.pass_context
def aml_click(ctx, address, max_depth):
    """
    Print funding chain (AML - Anti Money Laundering) for an address.

    Examples:
        aml 0x123...                        # Trace funding source
        aml 0x123... --max-depth 50         # Limit trace depth
    """
    console = ctx.obj
    addr = Web3.to_checksum_address(address)

    click.echo(f"Start: {addr}")
    i = 1

    while i <= max_depth:
        if not Web3.is_address(addr):
            break

        is_int_tx, tx = console.scan.get_first_tx(addr)
        if tx is None:
            break

        if is_int_tx:
            txid = tx["hash"]
            tx = console.web3.eth.get_transaction(txid)
            sender = tx["from"]
            to = tx["to"]
            name = console.scan.get_contract_name(to)

            click.echo(f"[{i}] {sender} calls contract {name}({to}) in {txid}")

            if "Tornado" in name:
                # Tornado.cash found, no sense to continue searching
                click.echo("Tornado Cash detected - stopping trace")
                break
        else:
            sender = tx["from"]
            to = tx["to"]
            value = int(tx["value"])
            ethers = console.web3.from_wei(value, "ether")
            click.echo(f"[{i}] {sender} sends {to} {ethers:.5f} ETH")

        addr = sender
        i += 1

    if i > max_depth:
        click.echo(f"Reached maximum depth of {max_depth}")

    click.echo("End")


@command_click(name="tx_replay")
@click.argument("txid")
@click.argument("sender", required=False)
@click.pass_context
def tx_replay_click(ctx, txid, sender):
    """
    Replay a transaction with a different sender to check for msg.sender validation.

    Examples:
        tx_replay 0x123...abc               # Replay with random sender
        tx_replay 0x123...abc 0x456...      # Replay with specific sender
    """
    console = ctx.obj

    if sender and not Web3.is_address(sender):
        click.echo(f"Invalid address: {sender}", err=True)
        return

    if not sender:
        # Random address with no ETH
        sender = "0x4459cD4ef34A3DCeC05b32e4f76A6e4306176e6f"

    tx = console.web3.eth.get_transaction(txid)
    block_number = tx["blockNumber"] - 1

    click.echo(
        f"Replaying (eth_call) {txid} at block {block_number} with sender {sender}:"
    )

    try:
        r = console.web3.eth.call(
            {
                "from": sender,
                "to": tx["to"],
                "data": tx["input"],
                "value": tx["value"],
            },
            block_number,
        )
        click.echo("Replay succeeded. eth_call returns:")
        click.echo(r.hex() if isinstance(r, bytes) else r)
    except Exception as e:
        click.echo("Replay failed.")
        click.echo(str(e))


@command_click(name="trace_tx")
@click.argument("txid")
@click.option("--tracer", default="legacy_tracer.js", help="JavaScript tracer to use")
@click.pass_context
def trace_tx_click(ctx, txid, tracer):
    """
    Print transaction trace using debug RPC.

    Examples:
        trace_tx 0x123...abc                # Trace transaction
        trace_tx 0x123...abc --tracer custom.js  # Use custom tracer

    Note: Requires a debug-enabled RPC endpoint.
    """
    console = ctx.obj

    tracer_obj = GethTracer(console.peth.rpc_url, tracer)
    result = tracer_obj.trace_transaction(txid)
    trace = TxTrace(console.peth.chain, result)
    trace.print()


@command_click(name="trace_call")
@click.argument("to")
@click.argument("calldata")
@click.argument("sender", required=False)
@click.argument("value", required=False)
@click.option("--tracer", default="legacy_tracer.js", help="JavaScript tracer to use")
@click.pass_context
def trace_call_click(ctx, to, calldata, sender, value, tracer):
    """
    Trace a call using debug RPC.

    Examples:
        trace_call 0x123... 0x456...        # Basic call trace
        trace_call 0x123... 0x456... 0x789...  # With sender
        trace_call 0x123... 0x456... 0x789... 1000000  # With value

    Note: Requires a debug-enabled RPC endpoint.
    """
    console = ctx.obj

    if not sender:
        sender = console.peth.sender
    if not value:
        value = 0

    tracer_obj = GethTracer(console.peth.rpc_url, tracer)
    result = tracer_obj.trace_call(
        {"to": to, "from": sender, "data": calldata, "value": value}
    )
    trace = TxTrace(console.peth.chain, result)
    trace.print()


@command_click(name="evm_trace_tx")
@click.argument("txid")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--depth", type=int, default=9, help="Trace depth to display")
@click.pass_context
def evm_trace_tx_click(ctx, txid, debug, depth):
    """
    Simulate transaction in built-in EVM and print trace.

    Examples:
        evm_trace_tx 0x123...abc            # Trace transaction
        evm_trace_tx 0x123...abc --debug    # With debug output
        evm_trace_tx 0x123...abc --depth 15 # Custom trace depth

    Note: This uses a simplified EVM that:
    - Does not measure gas
    - Does not support precompile contracts
    - Simulates in the block prior to the transaction
    """
    console = ctx.obj

    tx = console.web3.eth.get_transaction(txid)
    block_number = tx["blockNumber"] - 1

    if debug:
        Chain.debug = True
        VM.debug = True
    VM.trace = True

    chain = Chain(ForkChain(console.web3, block_number))

    r = chain.apply_transaction(
        Transaction(
            sender=tx["from"],
            to=tx["to"],
            value=tx["value"],
            data=HexBytes(tx["input"]),
        )
    )
    r.trace.print(depth)


@command_click(name="evm_trace_call")
@click.argument("to")
@click.argument("calldata")
@click.argument("sender", required=False)
@click.argument("value", required=False)
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--depth", type=int, default=9, help="Trace depth to display")
@click.pass_context
def evm_trace_call_click(ctx, to, calldata, sender, value, debug, depth):
    """
    Simulate call in built-in EVM and print trace.

    Examples:
        evm_trace_call 0x123... 0x456...    # Basic call trace
        evm_trace_call 0x123... 0x456... 0x789...  # With sender
        evm_trace_call 0x123... 0x456... 0x789... 1000000  # With value
        evm_trace_call 0x123... 0x456... --debug  # With debug output
    """
    console = ctx.obj

    if not sender:
        sender = console.peth.sender
    if not value:
        value = 0

    if debug:
        Chain.debug = True
        VM.debug = True
    VM.trace = True

    chain = Chain(ForkChain(console.web3))

    r = chain.apply_transaction(
        Transaction(sender=sender, to=to, value=value, data=HexBytes(calldata))
    )
    r.trace.print(depth)
