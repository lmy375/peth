"""
Ethereum and blockchain related commands using Click framework.
"""

import json
import os
import time
from datetime import datetime

import click

from peth.core.registry import command_click


@command_click(name="eth_call")
@click.argument("to")
@click.argument("calldata")
@click.argument("sender", required=False)
@click.argument("value", required=False)
@click.pass_context
def eth_call_click(ctx, to, calldata, sender, value):
    """
    Make an eth_call to a contract.

    Examples:
        eth_call 0x123... 0x456...          # Basic call
        eth_call 0x123... 0x456... 0x789... # With sender
        eth_call 0x123... 0x456... 0x789... 1000 # With value
    """
    console = ctx.obj

    if not sender:
        sender = console.peth.sender
    if not value:
        value = 0

    try:
        ret = console.web3.eth.call(
            {
                "from": console.web3.to_checksum_address(sender),
                "to": console.web3.to_checksum_address(to),
                "data": calldata,
                "value": int(value),
            },
            "latest",
        )
        click.echo("Returns:")
        click.echo(ret.hex())
    except Exception as e:
        click.echo("Error:")
        click.echo(str(e))


@command_click(name="estimate_gas")
@click.argument("to")
@click.argument("calldata")
@click.argument("sender", required=False)
@click.argument("value", required=False, default="0")
@click.pass_context
def estimate_gas_click(ctx, to, calldata, sender, value):
    """
    Estimate gas for a transaction.

    Examples:
        estimate_gas 0x123... 0x456...      # Basic estimation
        estimate_gas 0x123... 0x456... 0x789... # With sender
        estimate_gas 0x123... 0x456... 0x789... 1000 # With value
    """
    console = ctx.obj

    if not sender:
        sender = console.peth.sender

    try:
        ret = console.web3.eth.estimate_gas(
            {
                "from": console.web3.to_checksum_address(sender),
                "to": console.web3.to_checksum_address(to),
                "data": calldata,
                "value": int(value),
                "gas": 0,
                "gasPrice": 0,
            },
            "latest",
        )
        click.echo(f"Gas: {ret}")
    except Exception as e:
        click.echo("Error:")
        click.echo(str(e))


@command_click(name="call")
@click.argument("to")
@click.argument("sig_or_name")
@click.argument("args", nargs=-1)
@click.pass_context
def call_click(ctx, to, sig_or_name, args):
    """
    Call a contract function by signature or name.

    Examples:
        call 0x123... balanceOf 0x456...    # Call by name
        call 0x123... "balanceOf(address)" 0x456... # Call by signature
        call 0x123... totalSupply            # No arguments
    """
    console = ctx.obj
    arg_list = console._parse_args(list(args))
    result = console.peth.call_contract(to, sig_or_name, arg_list, silent=False)
    click.echo(result)


@command_click(name="rpc_call")
@click.argument("method")
@click.argument("args", nargs=-1)
@click.pass_context
def rpc_call_click(ctx, method, args):
    """
    Make a direct JSON-RPC call.

    Examples:
        rpc_call eth_getBalance 0x123... latest
        rpc_call eth_chainId
        rpc_call eth_blockNumber
        rpc_call web3_clientVersion
        rpc_call eth_gasPrice
        rpc_call txpool_status

    Reference:
    - https://ethereum.org/en/developers/docs/apis/json-rpc/
    - https://geth.ethereum.org/docs/interacting-with-geth/rpc
    """
    console = ctx.obj
    result = console.peth.rpc_call(method, list(args))
    click.echo(json.dumps(result, indent=2))


@command_click(name="tx_raw")
@click.argument("txid")
@click.pass_context
def tx_raw_click(ctx, txid):
    """
    Print raw transaction information.

    Examples:
        tx_raw 0x123...abc                  # Show transaction details
    """
    console = ctx.obj

    click.echo("Transaction:")
    tx = console.web3.eth.get_transaction(txid)
    console._print_json(tx, True)

    click.echo("\nReceipt:")
    console._print_json(console.web3.eth.get_transaction_receipt(txid), True)


@command_click(name="address")
@click.argument("address")
@click.option("--code", is_flag=True, help="Show code size details")
@click.pass_context
def address_click(ctx, address, code):
    """
    Print account information.

    Examples:
        address 0x123...                     # Basic info
        address 0x123... --code              # Include code details
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)

    balance = console.web3.eth.get_balance(addr)
    ether = float(console.web3.from_wei(balance, "ether"))
    click.echo(f"Balance: {balance} Wei ({ether:.4f} Ether)")

    nonce = console.web3.eth.get_transaction_count(addr)
    click.echo(f"Nonce: {nonce}")

    code_bytes = console.web3.eth.get_code(addr)
    code_size = len(code_bytes)
    click.echo(f"Code Size: {code_size} bytes")

    if code_size > 0 and code:
        click.echo(f"Code Hash: {console.web3.keccak(code_bytes).hex()}")


@command_click(name="storage")
@click.argument("address")
@click.argument("slot", required=False)
@click.option(
    "--range", "-r", "slot_range", type=int, default=16, help="Number of slots to show"
)
@click.pass_context
def storage_click(ctx, address, slot, slot_range):
    """
    Get storage of an address.

    Examples:
        storage 0x123...                     # Show first 16 slots
        storage 0x123... 0                   # Show specific slot
        storage 0x123... 0x10                # Hex slot number
        storage 0x123... --range 32          # Show first 32 slots
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)

    if slot is not None:
        # Parse slot number
        try:
            slot_num = int(slot)
        except ValueError:
            try:
                slot_num = int(slot, 16)
            except ValueError:
                click.echo(
                    f"Error: Invalid slot '{slot}' (must be hex/dec number)", err=True
                )
                return

        value = console.web3.eth.get_storage_at(addr, slot_num)
        click.echo(f"{hex(slot_num)} : {value.hex()}")
    else:
        # Show range of slots
        for slot_num in range(slot_range):
            value = console.web3.eth.get_storage_at(addr, slot_num)
            click.echo(f"{hex(slot_num)} : {value.hex()}")


@command_click(name="send_tx")
@click.argument("data")
@click.argument("to", required=False)
@click.argument("value", required=False)
@click.option("--gas-price", type=int, help="Gas price in gwei")
@click.option("--gas-limit", type=int, help="Gas limit")
@click.option("--nonce", type=int, help="Transaction nonce")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def send_tx_click(ctx, data, to, value, gas_price, gas_limit, nonce, yes):
    """
    Send a transaction (requires signer to be set).

    DANGER: This sends real transactions! Use with caution!

    Examples:
        send_tx 0x123...                     # Send data to create contract
        send_tx 0x123... 0x456...            # Send data to address
        send_tx 0x123... 0x456... 1000000    # With value
        send_tx 0x123... 0x456... --yes      # Skip confirmation

    Use 'signer' command to set your private key before using send_tx.
    """
    console = ctx.obj

    if not console.peth.signer:
        click.echo("Error: Use 'signer' command to set your key first.", err=True)
        return

    # Parse arguments
    args = console._parse_args([data, to, value] if to else [data])
    data = args[0]
    to = args[1] if len(args) > 1 else None
    value = args[2] if len(args) > 2 else None

    # Prepare transaction
    tx, signed_tx = console.peth.send_transaction(data, to, value, dry_run=True)

    click.echo("TX info:")
    console._print_json(tx, True)

    click.echo("\nSignature info:")
    tx_hash = signed_tx.hash.hex()
    click.echo(f"  Hash: {tx_hash}")
    click.echo(f"  Raw Transaction: {signed_tx.rawTransaction.hex()}")
    click.echo(f"  r: {signed_tx.r}")
    click.echo(f"  s: {signed_tx.s}")
    click.echo(f"  v: {signed_tx.v}")
    click.echo(f"\nRPC: {console.peth.rpc_url}")

    if not yes:
        if not click.confirm("Send transaction?"):
            click.echo("Cancelled.")
            return

    # Send transaction
    current_block = console.peth.web3.eth.block_number
    console.peth.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    click.echo(f"Sent {tx_hash}. Current block {current_block}")

    # Wait for confirmation
    with click.progressbar(label="Waiting for confirmation"):
        while True:
            new_block = console.peth.web3.eth.block_number
            if new_block == current_block:
                time.sleep(1)
                continue

            click.echo(f"\nNew block {new_block}")
            current_block = new_block

            try:
                rcpt = console.web3.eth.get_transaction_receipt(tx_hash)
                # Show transaction details
                try:
                    ctx.invoke(tx_click, args=(tx_hash,))
                except Exception:
                    pass
                click.echo("\nFull Receipt:")
                console._print_json(rcpt, True)
                break
            except Exception as e:
                click.echo(str(e))


@command_click(name="log")
@click.argument("args", nargs=-1)
@click.option("--address", "-a", help="Filter by contract address")
@click.option("--topic0", "-t0", help="Filter by topic 0")
@click.option("--topic1", "-t1", help="Filter by topic 1")
@click.option("--topic2", "-t2", help="Filter by topic 2")
@click.option("--topic3", "-t3", help="Filter by topic 3")
@click.option("--blocks", "-b", type=int, default=100, help="Blocks per scan")
@click.option("--loops", "-l", type=int, default=100, help="Number of scan loops")
@click.pass_context
def log_click(ctx, args, address, topic0, topic1, topic2, topic3, blocks, loops):
    """
    Search and print event logs.

    Examples:
        log                                  # Recent logs
        log --address 0x123...               # Logs from specific address
        log --topic0 0xddf252ad...           # Transfer events
        log --blocks 1000 --loops 10        # Scan 10,000 blocks
        log -a 0x123... -t0 0xddf252ad...   # Combined filters

    Use '-' or 'null' as placeholder for topics you want to skip.
    """
    console = ctx.obj

    # Build topics array
    topics = []
    for t in [topic0, topic1, topic2, topic3]:
        if t:
            if t in ["-", "null", "None"]:
                topics.append(None)
            else:
                if t.startswith("0x"):
                    t = t[2:]
                if len(t) != 64:
                    t = t.rjust(64, "0")
                topics.append("0x" + t)

    # Legacy argument parsing for backward compatibility
    if args and not address:
        for arg in args:
            if arg in ["-", "null", "None"]:
                topics.append(None)
            elif not address and len(arg) in (40, 42):
                address = arg
            elif len(arg) < 20:
                if arg.isdigit():
                    blocks = int(arg)
            else:
                if arg.startswith("0x"):
                    arg = arg[2:]
                if len(arg) != 64:
                    arg = arg.rjust(64, "0")
                arg = "0x" + arg
                topics.append(arg)

    click.echo("Search parameters:")
    click.echo(
        f"  - Scan {blocks} blocks × {loops} times = {blocks * loops} total blocks"
    )
    click.echo(f"  - Address: {address or 'Any'}")
    click.echo(f"  - Topics: {topics or 'Any'}")

    logs = console.peth.get_logs(address, topics, step=blocks, count=loops)

    for log in logs:
        if log.removed:
            continue

        tx_hash = log.transactionHash.hex()
        log_address = log.address
        data = log.data

        click.echo(f"\ntxid {tx_hash}")
        click.echo(f"  address {log_address}")
        for i, topic in enumerate(log.topics):
            click.echo(f"  topic[{i}] {topic.hex()}")
        click.echo(f"  data {data}")


@command_click(name="status")
@click.option(
    "--interval", "-i", type=float, default=1.0, help="Update interval in seconds"
)
@click.pass_context
def status_click(ctx, interval):
    """
    Monitor blockchain status in real-time.

    Examples:
        status                               # Default monitoring
        status --interval 0.5                # Faster updates
    """
    console = ctx.obj

    cur = console._get_block("latest")
    start_time = time.time()
    start_block_number = cur.number

    try:
        while True:
            total_blocks = cur.number - start_block_number or 1
            total_time = (time.time() - start_time) or 1

            click.echo(
                f"{datetime.now()} {total_blocks / total_time:.2f} b/s {total_time / total_blocks:.2f} s/b"
            )

            console._print_block("latest ", cur)

            while True:
                pending = console._get_block("pending")

                if pending.number and pending.number <= cur.number:
                    continue

                console._print_block("pending", pending)

                new_cur = console._get_block("latest")
                if new_cur.number >= cur.number + 1:
                    cur = new_cur
                    break
                else:
                    time.sleep(interval)
    except KeyboardInterrupt:
        click.echo("\nStopped.")


@command_click(name="blocks")
@click.pass_context
def blocks_click(ctx):
    """
    Show finalized, safe, and latest block information.

    Examples:
        blocks                               # Show block status
    """
    console = ctx.obj

    click.echo("Blocks:")

    finalized_block = console._get_block("finalized")
    console._print_block("finalized", finalized_block)

    safe_block = console._get_block("safe")
    console._print_block("safe", safe_block)

    latest_block = console._get_block("latest")
    console._print_block("latest", latest_block)

    safe_block_confs = latest_block.number - safe_block.number
    finalized_block_confs = latest_block.number - finalized_block.number

    safe_block_time = latest_block.timestamp - safe_block.timestamp
    finalized_block_time = latest_block.timestamp - finalized_block.timestamp

    click.echo(
        f"\nBlock rate: {finalized_block_confs / (finalized_block_time or 1):.2f} b/s "
        f"{finalized_block_time / (finalized_block_confs or 1):.2f} s/b"
    )
    click.echo(
        f"Safe gap: {safe_block_confs} blocks, {safe_block_time:.2f} secs = "
        f"{safe_block_time / 60:.2f} mins"
    )
    click.echo(
        f"Finalized gap: {finalized_block_confs} blocks, {finalized_block_time:.2f} secs = "
        f"{finalized_block_time / 60:.2f} mins"
    )


@command_click(name="run")
@click.argument("solidity_file")
@click.option("--sender", help="Override default sender")
@click.pass_context
def run_click(ctx, solidity_file, sender):
    """
    Execute Solidity code using eth_call.

    Your Solidity file should contain an 'Executor' contract with a 'run()' function:

    pragma solidity ^0.8.13;

    contract Executor {
        constructor() public payable {}

        function run() external returns(address, address, address){
            // Your code here
            return (msg.sender, tx.origin, address(this));
        }
    }

    Examples:
        run test.sol                         # Execute Solidity file
        run test.sol --sender 0x123...       # With custom sender
    """
    console = ctx.obj

    if not solidity_file.endswith(".sol"):
        click.echo(f"Error: .sol file needed but got {solidity_file}", err=True)
        return

    if not os.path.exists(solidity_file):
        click.echo(f"Error: File {solidity_file} not exists", err=True)
        return

    with open(solidity_file, encoding="utf-8") as f:
        code = f.read()

    if sender:
        old_sender = console.peth.sender
        console.peth.sender = sender
        result = console.peth.run_solidity(code)
        console.peth.sender = old_sender
    else:
        result = console.peth.run_solidity(code)

    click.echo(result)


# Import tx command from transaction module for backward compatibility
from .transaction import tx_click
