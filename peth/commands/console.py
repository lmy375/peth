"""
Console-related commands using Click framework.
"""

import os

import click
from eth_account import Account
from web3 import Web3

from peth.core.log import logger, logging
from peth.core.peth import Peth
from peth.core.registry import command_click
from peth.eth.scan import ScanAPI


@command_click(name="debug")
@click.pass_context
def debug_click(ctx):
    """
    Toggle debug flag. Once on, the console will raise exceptions instead of catching them.
    """
    console = ctx.obj
    console._debug = not console._debug
    if console._debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    click.echo(f"debug set to {console._debug}")


@command_click(name="chain")
@click.argument("chain_name", required=False)
@click.argument("api_version", required=False)
@click.pass_context
def chain_click(ctx, chain_name, api_version):
    """
    Display or change blockchain configuration.

    Examples:
        chain                       # Show current chain info
        chain eth                   # Switch to Ethereum
        chain bsc                   # Switch to BSC
        chain eth v2               # Switch to Ethereum with v2 API
        chain v2                   # List all v2 supported chains
        chain v2 137               # Switch to chain ID 137 with v2 API
    """
    console = ctx.obj

    # Show current chain info
    click.echo("Current:")
    click.echo(f"  Chain: {console.peth.chain}")
    try:
        click.echo(f"     Chain ID: {console.peth.web3.eth.chain_id}")
        click.echo(f"     Block number: {console.peth.web3.eth.block_number}")
    except Exception:
        pass
    click.echo(f"  RPC: {console.peth.rpc_url}")
    click.echo(f"  API: {console.peth.api_url}")
    click.echo(f"  Address: {console.peth.address_url}")
    if hasattr(console.peth.scan, "use_v2") and console.peth.scan.use_v2:
        click.echo("  API Version: v2")

    if not chain_name:
        return

    # Handle "chain list [filter]" — list chains from chainid.network
    if chain_name == "list":
        from peth.core import chainlist

        try:
            chains = chainlist.get_chainlist()
        except Exception as e:
            click.echo(f"Failed to fetch chainid.network chainlist: {e}")
            return
        flt = (api_version or "").lower()
        rows = [
            c
            for c in chains
            if not flt
            or flt in c.get("name", "").lower()
            or flt in c.get("shortName", "").lower()
            or flt == str(c.get("chainId"))
        ]
        click.echo(f"\n{len(rows)} chain(s) from chainid.network:")
        click.echo(f"{'ChainID':<10} {'ShortName':<16} {'Name'}")
        click.echo("-" * 70)
        for c in sorted(rows, key=lambda x: x.get("chainId", 0)):
            click.echo(
                f"{c.get('chainId', ''):<10} {c.get('shortName', ''):<16} {c.get('name', '')}"
            )
        click.echo("\nUse 'chain <chainId|shortName|name>' to switch.")
        return

    # Handle "chain v2" commands
    if chain_name == "v2":
        if not api_version:
            # List v2 chains
            click.echo("\nFetching v2 supported chains...")
            chains = ScanAPI.get_v2_chainlist()
            if chains:
                click.echo(f"\nEtherscan v2 supports {len(chains)} chains:")
                click.echo(f"{'Chain ID':<12} {'Chain Name':<40} {'Status'}")
                click.echo("-" * 70)
                for chain in sorted(chains, key=lambda x: int(x["chainid"])):
                    status = (
                        "✓ Online"
                        if chain["status"] == 1
                        else "✗ Offline" if chain["status"] == 0 else "⚠ Degraded"
                    )
                    click.echo(
                        f"{chain['chainid']:<12} {chain['chainname']:<40} {status}"
                    )
                click.echo("\nUse 'chain v2 <chain_id>' to switch to a v2 chain")
            else:
                click.echo(
                    "Failed to fetch v2 chainlist. Make sure ETHERSCAN_API_KEY is set."
                )
            return

        # Switch to v2 chain by ID
        try:
            chain_id = int(api_version)

            # Fetch chainlist to get chain info
            chains = ScanAPI.get_v2_chainlist()
            chain_info = None
            if chains:
                for chain in chains:
                    if int(chain["chainid"]) == chain_id:
                        chain_info = chain
                        break

            if not chain_info:
                click.echo(f"Chain ID {chain_id} not found in v2 supported chains")
                return

            # Get RPC URL from chain_info if available, otherwise try to find in config
            rpc_url = None
            address_url = chain_info.get("blockexplorer", "")

            # Try to find RPC URL from existing config
            from peth.core.config import config

            for name, chain_config in config.chains.items():
                if (
                    isinstance(chain_config, dict)
                    and chain_config.get("chain_id") == chain_id
                ):
                    rpc_url = chain_config.get("rpc_url")
                    break

            # Create a v2 Peth instance
            if rpc_url:
                old_sender = console.peth.sender

                # Create Web3Ex instance
                scan_v2 = ScanAPI.get_or_create_v2(chain_id)
                console.peth = Peth(
                    rpc_url=rpc_url,
                    api_url="https://api.etherscan.io/v2/api",
                    address_url=address_url,
                    chain=chain_info["chainname"],
                    sender=old_sender,
                    use_v2=True,
                )
                console.peth.scan = scan_v2

                click.echo("Changed:")
                click.echo(f"  Chain: {chain_info['chainname']} (v2)")
                click.echo(f"     Chain ID: {chain_id}")
                try:
                    click.echo(
                        f"     Block number: {console.peth.web3.eth.block_number}"
                    )
                except Exception:
                    pass
                click.echo(f"  RPC: {rpc_url}")
                click.echo("  API: https://api.etherscan.io/v2/api")
                click.echo(f"  Explorer: {address_url}")
                click.echo("  API Version: v2")
            else:
                click.echo(
                    f"Chain {chain_info['chainname']} ({chain_id}) found but no RPC URL available"
                )
                click.echo(
                    "You can still use the v2 scan API but Web3 functions won't work"
                )

        except ValueError:
            click.echo(f"Invalid chain ID: {api_version}")
        return

    # Handle "chain <name> v2" or "chain <name>"
    use_v2 = api_version == "v2"

    from peth.core.config import config

    if chain_name in config.chains:
        old_sender = console.peth.sender
        console.peth = Peth.get_or_create(chain_name, use_v2=use_v2)
        console.peth.sender = old_sender  # Keep the sender value.
        click.echo("Changed:")
        click.echo(f"  Chain: {console.peth.chain}")
        try:
            click.echo(f"     Chain ID: {console.peth.web3.eth.chain_id}")
            click.echo(f"     Block number: {console.peth.web3.eth.block_number}")
        except Exception:
            pass
        click.echo(f"  RPC: {console.peth.rpc_url}")
        click.echo(f"  API: {console.peth.api_url}")
        click.echo(f"  Address: {console.peth.address_url}")
        if hasattr(console.peth.scan, "use_v2") and console.peth.scan.use_v2:
            click.echo("  API Version: v2")
    else:
        # Fall back to chainid.network lookup
        from peth.core import chainlist

        try:
            entry = chainlist.find_chain(chain_name)
        except Exception as e:
            click.echo(f"Failed to query chainid.network: {e}")
            click.echo(f"Supported chains (yaml): {', '.join(config.chains.keys())}")
            return

        if not entry:
            click.echo(
                f"Chain '{chain_name}' not found in chains.yaml or chainid.network."
            )
            click.echo(f"Supported chains (yaml): {', '.join(config.chains.keys())}")
            click.echo("Try: 'chain list' or 'chain list <filter>'.")
            return

        rpc_url = chainlist.pick_rpc(entry)
        if not rpc_url:
            click.echo(
                f"Found {entry.get('name')} (chainId {entry.get('chainId')}) "
                "but no usable HTTPS RPC URL (all entries require API keys)."
            )
            return

        explorer = chainlist.pick_explorer(entry)
        address_url = (explorer.rstrip("/") + "/address/") if explorer else ""

        chain_id = entry.get("chainId")
        api_url = ""
        scan_v2 = None
        try:
            v2_chains = ScanAPI.get_v2_chainlist() or []
            if any(int(c.get("chainid", -1)) == chain_id for c in v2_chains):
                api_url = "https://api.etherscan.io/v2/api"
                scan_v2 = ScanAPI.get_or_create_v2(chain_id)
                use_v2 = True
        except Exception:
            pass

        old_sender = console.peth.sender
        console.peth = Peth(
            rpc_url=rpc_url,
            api_url=api_url,
            address_url=address_url,
            chain=entry.get("shortName") or entry.get("name"),
            sender=old_sender,
            use_v2=use_v2,
        )
        if scan_v2 is not None:
            console.peth.scan = scan_v2

        click.echo("Changed (via chainid.network):")
        click.echo(f"  Chain: {console.peth.chain}")
        click.echo(f"     Chain ID: {chain_id}")
        try:
            click.echo(f"     Block number: {console.peth.web3.eth.block_number}")
        except Exception:
            pass
        click.echo(f"  RPC: {rpc_url}")
        click.echo(f"  API: {api_url or '(none)'}")
        click.echo(f"  Address: {address_url or '(none)'}")
        if use_v2:
            click.echo("  API Version: v2")


@command_click(name="config")
@click.argument("action", required=False)
@click.argument("section", required=False)
@click.argument("key", required=False)
@click.argument("value", required=False)
@click.pass_context
def config_click(ctx, action, section, key, value):
    """
    Manage configuration settings.

    Examples:
        config                              # Print current settings
        config raw                          # Print raw INI settings
        config set general timeout 30       # Change a setting
    """
    from peth.core.config import config

    if not action:
        config.print_config()
    elif action == "raw":
        config.print_ini()
    elif action == "set" and section and key and value:
        config.cfg.set(section, key, value)
        click.echo(f"Set [{section}] {key} = {value}")
    else:
        click.echo("Usage: config [raw | set <section> <key> <value>]")


@command_click(name="sender")
@click.argument("address", required=False)
@click.pass_context
def sender_click(ctx, address):
    """
    Get or set default sender address for eth_call.

    Examples:
        sender                              # Show current sender
        sender 0x123...                     # Set new sender address
    """
    console = ctx.obj
    click.echo(f"Current: {console.peth.sender}")

    if address and Web3.is_address(address):
        console.peth.sender = address
        click.echo(f"New:     {console.peth.sender}")
    elif address:
        click.echo("Invalid address format", err=True)


@command_click(name="signer")
@click.argument("private_key", required=False)
@click.option(
    "--show-address", is_flag=True, help="Show address for private key without setting"
)
@click.pass_context
def signer_click(ctx, private_key, show_address):
    """
    Get or set signer for send_tx. DANGEROUS!

    Examples:
        signer                              # Show current signer
        signer 0x123...                     # Set signer private key
        signer 0x123... --show-address      # Show address without setting
    """
    console = ctx.obj

    if console.peth.signer:
        click.echo(f"Current: {console.peth.signer.address}")
    else:
        click.echo("Current: Not set.")

    if private_key:
        try:
            signer = Account.from_key(private_key)
            if show_address:
                click.echo(f"Address: {signer.address}")
            else:
                console.peth.signer = signer
                click.echo(f"New:     {console.peth.signer.address}")
        except Exception as e:
            click.echo(f"Invalid private key: {e}", err=True)


@command_click(name="sh")
@click.argument("command", nargs=-1, required=True)
@click.pass_context
def sh_click(ctx, command):
    """
    Run system shell command.

    Examples:
        sh ls -la                           # List files
        sh git status                       # Check git status
    """
    cmd = " ".join(command)
    os.system(cmd)


@command_click(name="py")
@click.argument("expression")
@click.option(
    "--exec", "exec_mode", is_flag=True, help="Execute as statement instead of eval"
)
@click.pass_context
def py_click(ctx, expression, exec_mode):
    """
    Evaluate or execute Python expression.

    Examples:
        py "2 + 2"                          # Evaluate expression
        py "import sys; print(sys.version)" --exec  # Execute statement
    """
    console = ctx.obj

    # Make common objects available
    namespace = {
        "console": console,
        "peth": console.peth,
        "web3": console.web3,
        "Web3": Web3,
    }

    try:
        if exec_mode:
            exec(expression, namespace)
        else:
            result = eval(expression, namespace)
            if result is not None:
                click.echo(result)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@command_click(name="ipython")
@click.pass_context
def ipython_click(ctx):
    """
    Start IPython console with access to peth objects.

    Available objects:
        web3    - Web3 instance
        eth     - web3.eth shortcut
        peth    - Peth instance
        console - Console instance
    """
    console = ctx.obj

    peth = console.peth  # noqa: F841
    web3 = console.web3  # noqa: F841
    eth = web3.eth  # noqa: F841

    # Import IPython
    try:
        import IPython

        IPython.embed(colors="Linux")
    except ImportError:
        click.echo("IPython not installed. Install with: pip install ipython", err=True)


@command_click(name="open")
@click.argument("path")
@click.pass_context
def open_click(ctx, path):
    """
    Open URL or file in default application.

    Examples:
        open https://etherscan.io           # Open website
        open /path/to/file.txt              # Open file
    """
    os.system(f"open {path}")


@command_click(name="exit")
@click.option("--force", "-f", is_flag=True, help="Force exit without confirmation")
@click.pass_context
def exit_click(ctx, force):
    """
    Exit the console.

    Examples:
        exit                                # Exit console
        exit --force                        # Force exit without confirmation
    """
    if not force:
        click.echo("bye!")
    return True
