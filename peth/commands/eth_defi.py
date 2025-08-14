"""
DeFi and protocol-specific commands using Click framework.
"""

import click

from peth.core.registry import command_click
from peth.eth.utils import convert_value_list


@command_click(name="view")
@click.argument("contract")
@click.argument("name")
@click.argument("type", required=False)
@click.argument("length", required=False)
@click.pass_context
def view_click(ctx, contract, name, type, length):
    """
    Call property-like view methods on contracts.

    Examples:
        view 0x123... admin                  # Call admin()
        view 0x123... admin address          # Call admin()->(address)
        view 0x123... name string            # Call name()->(string)
        view 0x123... addrs address 10       # Call addrs(uint256)->(address) for i=0..9
        view 0x123... addrs address addrs_length  # Use another view for length
    """
    console = ctx.obj

    if type and length:
        # Array-like view
        try:
            length_int = int(length)
        except ValueError:
            # Length is another view method
            length_int = console.peth.get_view_value(contract, length, "uint256")

        sig = f"{name}(uint256)->({type})"
        for i in range(length_int):
            value = console.peth.call_contract(contract, sig, [i])
            click.echo(f"[{i}]\t{value}")

            if not value:
                click.echo("None found. Stopping.")
                break
    else:
        # Simple view
        value = console.peth.get_view_value(contract, name, type)
        click.echo(value)


@command_click(name="erc20")
@click.argument("address")
@click.argument("function", required=False)
@click.argument("args", nargs=-1)
@click.pass_context
def erc20_click(ctx, address, function, args):
    """
    Print ERC20 token information or call functions.

    Examples:
        erc20 0x123...                       # Show token info
        erc20 0x123... balanceOf 0x456...    # Check balance
        erc20 0x123... allowance 0x456... 0x789...  # Check allowance
    """
    console = ctx.obj

    if not function:
        # Show token info
        methods = [
            ("Name:", "name()->(string)"),
            ("Symbol:", "symbol()->(string)"),
            ("Decimals:", "decimals()->(uint256)"),
            ("Total Supply:", "totalSupply()->(uint256)"),
        ]

        token = console._parse_args(address, "address")
        for name, method in methods:
            try:
                value = console.peth.call_contract(token, method, silent=True)
                click.echo(f"{name} {value}")
            except Exception:
                click.echo(f"{name} <unavailable>")
    else:
        # Call specific function
        call_args = convert_value_list(list(args))

        sigs = [
            "totalSupply() -> (uint256)",
            "balanceOf(address) -> (uint256)",
            "allowance(address, address) -> (uint256)",
            "name() -> (string)",
            "symbol() -> (string)",
            "decimals() -> (uint8)",
        ]

        try:
            sig = next(s for s in sigs if s.startswith(function))
        except StopIteration:
            click.echo(f"{function} is not a valid ERC20 method", err=True)
            return

        value = console.peth.call_contract(address, sig, call_args)
        click.echo(value)


@command_click(name="proxy")
@click.argument("addresses", nargs=-1, required=True)
@click.option("--all", "show_all", is_flag=True, help="Show all proxy slots")
@click.pass_context
def proxy_click(ctx, addresses, show_all):
    """
    Print ERC1967 proxy information.

    Examples:
        proxy 0x123...                       # Check single proxy
        proxy 0x123... 0x456...              # Check multiple proxies
        proxy 0x123... --all                 # Show all slots
    """
    console = ctx.obj

    def print_slot_as_address(name, slot):
        bytes32 = console.web3.eth.get_storage_at(addr, slot)
        if int(bytes32.hex(), 16) != 0:
            addr_hex = "0x" + bytes32[12:].hex()
            click.echo(f"{name}: {console._get_full_name(addr_hex)}")

    for address in addresses:
        if len(addresses) > 1:
            click.echo(f"\n=== {address} ===")

        addr = console.web3.to_checksum_address(address)

        # ERC1967 slots
        impl = console.web3.eth.get_storage_at(
            addr, 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
        )[12:].hex()
        admin = console.web3.eth.get_storage_at(
            addr, 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103
        )[12:].hex()
        beacon = console.web3.eth.get_storage_at(
            addr, 0xA3F0AD74E5423AEBFD80D3EF4346578335A9A72AEAEE59FF6CB3582B35133D50
        )[12:].hex()

        impl_addr = "0x" + impl
        admin_addr = "0x" + admin
        beacon_addr = "0x" + beacon

        if int(impl, 16) == 0 and int(beacon, 16) == 0:
            click.echo(f"{addr} may not be an ERC-1967 Proxy")
            if show_all:
                click.echo("Checking common proxy slots:")
                print_slot_as_address("Slot[0]", 0)
                print_slot_as_address("Slot[1]", 1)
                print_slot_as_address("Slot[2]", 2)
                print_slot_as_address("Slot[3]", 3)
        else:
            click.echo(f"{addr} is an ERC-1967 Proxy")
            click.echo(f"Implementation: {console._get_full_name(impl_addr)}")

            admin_name = console._get_full_name(admin_addr)
            click.echo(f"Admin: {admin_name}")
            click.echo(f"Beacon: {console._get_full_name(beacon_addr)}")

            print_slot_as_address(
                "Rollback",
                0x4910FDFA16FED3260ED0E7147F7CC6DA11A60208B5B9406D12A635614FFD9143,
            )

            if "ProxyAdmin" in admin_name:
                click.echo("\nProxyAdmin owner:")
                ctx.invoke(owner_click, address=admin_addr)


@command_click(name="proxy_all")
@click.argument("addresses", nargs=-1, required=True)
@click.pass_context
def proxy_all_click(ctx, addresses):
    """
    Show only proxy implementation addresses (compact format).

    Examples:
        proxy_all 0x123... 0x456... 0x789... # Check multiple addresses
    """
    console = ctx.obj

    for address in addresses:
        addr = console.web3.to_checksum_address(address)
        impl = console.web3.eth.get_storage_at(
            addr, 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
        )[12:].hex()

        if int(impl, 16) != 0:
            impl_addr = "0x" + impl
            name = console.peth.scan.get_contract_name(addr)
            if not name:
                name = ""
            click.echo(f"Proxy {name} {addr} impl {impl_addr}")


@command_click(name="owner")
@click.argument("address")
@click.pass_context
def owner_click(ctx, address):
    """
    Print contract owner (for Ownable contracts).

    Examples:
        owner 0x123...                       # Get owner address
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)

    try:
        owner = console.peth.call_contract(addr, "owner()->(address)")
        click.echo(f"Owner: {console._get_full_name(owner)}")
    except Exception as e:
        click.echo(f"Error: Ensure the address is an Ownable contract. {e}", err=True)


@command_click(name="safe")
@click.argument("address")
@click.option("--modules", is_flag=True, help="Show enabled modules")
@click.pass_context
def safe_click(ctx, address, modules):
    """
    Print Gnosis Safe multisig information.

    Examples:
        safe 0x123...                        # Basic Safe info
        safe 0x123... --modules              # Include modules
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)

    try:
        version = console.peth.call_contract(addr, "VERSION()->(string)", silent=True)
        click.echo(f"Version: {version}")
    except Exception:
        click.echo("Version: <unavailable>")

    try:
        threshold = console.peth.call_contract(addr, "getThreshold()->(uint)")
        users = console.peth.call_contract(addr, "getOwners()->(address[])")

        if users:
            click.echo(f"Policy: {threshold}/{len(users)}")
            click.echo("Owners:")
            for u in users:
                click.echo(f"  {console._get_full_name(u)}")
        else:
            click.echo("No owners found")
    except Exception as e:
        click.echo(f"Error getting Safe info: {e}", err=True)
        return

    try:
        impl = console.peth.call_contract(addr, "masterCopy()->(address)", silent=True)
        if impl:
            click.echo(f"Implementation: {impl}")
    except Exception:
        pass

    # Fallback handler
    fallback = console.web3.eth.get_storage_at(
        addr, 0x6C9A6C4A39284E37ED1CF53D337577D14212A4870FB976A4366C693B939918D5
    )[12:].hex()
    if int(fallback, 16) != 0:
        click.echo(f"Fallback handler: {console._get_full_name('0x' + fallback)}")

    # Guard
    guard = console.web3.eth.get_storage_at(
        addr, 0x4A204F620C8C5CCDCA3FD54D003BADD85BA500436A431F0CBDA4F558C93C34C8
    )[12:].hex()
    if int(guard, 16) != 0:
        click.echo(f"Guard: {console._get_full_name('0x' + guard)}")

    if modules:
        try:
            module_list = console.peth.call_contract(
                addr,
                "getModulesPaginated(address,uint256)->(address[],address)",
                ["0x0000000000000000000000000000000000000001", 100],
            )[0]

            if module_list:
                click.echo("Modules:")
                for m in module_list:
                    click.echo(f"  {console._get_full_name(m)}")
        except Exception:
            pass


@command_click(name="timelock")
@click.argument("address")
@click.pass_context
def timelock_click(ctx, address):
    """
    Print TimelockController delay information.

    Examples:
        timelock 0x123...                    # Show timelock delays
    """
    console = ctx.obj
    addr = console.web3.to_checksum_address(address)

    # Try different method names
    delay_methods = [
        ("Min Delay", "getMinDelay()->(uint)"),
        ("Min Delay", "MINIMUM_DELAY()->(uint)"),
        ("Max Delay", "MAXIMUM_DELAY()->(uint)"),
        ("Current Delay", "delay()->(uint)"),
    ]

    found_any = False
    for name, method in delay_methods:
        try:
            secs = console.peth.call_contract(addr, method, silent=True)
            if secs is not None:
                click.echo(f"{name}: {secs}s = {secs/3600:.2f}h")
                found_any = True
        except Exception:
            pass

    # Try to get admin
    try:
        admin = console.peth.call_contract(addr, "admin()->(address)", silent=True)
        if admin:
            click.echo(f"Admin: {console._get_full_name(admin)}")
            found_any = True
    except Exception:
        pass

    if not found_any:
        click.echo(
            "No timelock information found. Is this a TimelockController?", err=True
        )


@command_click(name="pair")
@click.argument("args", nargs=-1, required=True)
@click.option("--v3", is_flag=True, help="Show Uniswap V3 specific info")
@click.pass_context
def pair_click(ctx, args, v3):
    """
    Print token pair information (Uniswap/PancakeSwap).

    Examples:
        pair 0x123...                        # Show pair info by address
        pair 0x123... 0x456...               # Find pair for two tokens
        pair 0x123... 0x456... 0x789...      # Use specific factory
    """
    console = ctx.obj

    pair_addr = None
    factory = None

    if len(args) == 1:
        # Direct pair address
        pair_addr = args[0]
    elif len(args) == 2:
        # Two token addresses
        addr1, addr2 = args
    elif len(args) == 3:
        # Two tokens + factory
        addr1, addr2, factory = args
    else:
        click.echo("Invalid arguments. See 'help pair'", err=True)
        return

    if pair_addr:
        # Get tokens from pair
        try:
            addr1 = console.peth.call_contract(pair_addr, "token0()->(address)")
            addr2 = console.peth.call_contract(pair_addr, "token1()->(address)")
        except Exception as e:
            click.echo(f"Error getting tokens from pair: {e}", err=True)
            return
    else:
        # Find pair from tokens
        if factory is None:
            if console.peth.chain == "eth":
                factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"  # Uniswap V2
            elif console.peth.chain == "bsc":
                factory = "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"  # PancakeSwap
            else:
                click.echo(
                    "No default factory for this chain. Please specify factory address.",
                    err=True,
                )
                return

        pair_addr = console.peth.call_contract(
            factory, "getPair(address,address)->(address)", [addr1, addr2]
        )

        if pair_addr == "0x0000000000000000000000000000000000000000":
            click.echo("Token pair not found in factory.", err=True)
            return

    click.echo(f"Token Pair: {pair_addr}")

    # Get token info
    try:
        token0_name = console.peth.call_contract(addr1, "symbol()->(string)")
        token0_decimal = console.peth.call_contract(addr1, "decimals()->(uint)")

        token1_name = console.peth.call_contract(addr2, "symbol()->(string)")
        token1_decimal = console.peth.call_contract(addr2, "decimals()->(uint)")

        click.echo(f"{token0_name} {addr1} decimals: {token0_decimal}")
        click.echo(f"{token1_name} {addr2} decimals: {token1_decimal}")

        # Get reserves
        r0 = console.peth.call_contract(
            addr1, "balanceOf(address)->(uint)", [pair_addr]
        )
        r1 = console.peth.call_contract(
            addr2, "balanceOf(address)->(uint)", [pair_addr]
        )

        # Check for V3 fee
        fee = console.peth.call_contract(pair_addr, "fee()->(uint)", silent=True)
        if fee:
            click.echo(f"V3 Fee: {fee/1e4:.2f}%")
            if v3:
                # Additional V3 info
                try:
                    slot0 = console.peth.call_contract(
                        pair_addr,
                        "slot0()->(uint160,int24,uint16,uint16,uint16,uint8,bool)",
                    )
                    if slot0:
                        sqrt_price = slot0[0]
                        tick = slot0[1]
                        click.echo(f"V3 sqrtPriceX96: {sqrt_price}")
                        click.echo(f"V3 current tick: {tick}")
                except Exception:
                    pass

        # Calculate prices
        r0_decimal = r0 / (10**token0_decimal)
        r1_decimal = r1 / (10**token1_decimal)
        click.echo(
            f"Reserves: {r0_decimal:.4f} {token0_name}, {r1_decimal:.4f} {token1_name}"
        )

        if fee is None and r0_decimal > 0 and r1_decimal > 0:
            # V2 price calculation
            click.echo("\nV2 Price:")
            click.echo(f"1 {token0_name} = {r1_decimal/r0_decimal:.4f} {token1_name}")
            click.echo(f"1 {token1_name} = {r0_decimal/r1_decimal:.4f} {token0_name}")

    except Exception as e:
        click.echo(f"Error getting pair info: {e}", err=True)


@command_click(name="factory")
@click.argument("factory_address")
@click.option("--limit", "-l", type=int, default=10, help="Maximum pairs to show")
@click.option("--start", "-s", type=int, default=0, help="Starting index")
@click.pass_context
def factory_click(ctx, factory_address, limit, start):
    """
    List pairs from a DEX factory contract.

    Examples:
        factory 0x123...                     # Show first 10 pairs
        factory 0x123... --limit 50          # Show first 50 pairs
        factory 0x123... --start 100 --limit 20  # Show pairs 100-119
    """
    console = ctx.obj
    factory = console.web3.to_checksum_address(factory_address)

    try:
        total_pairs = console.peth.call_contract(factory, "allPairsLength()->(uint256)")
        click.echo(f"{total_pairs} total pairs found.")

        end = min(start + limit, total_pairs)
        click.echo(f"Showing pairs {start} to {end-1}:\n")

        for i in range(start, end):
            try:
                pair = console.peth.call_contract(
                    factory, "allPairs(uint256)->(address)", [i]
                )
                click.echo(f"[{i}] {pair}")

                # Get basic pair info
                try:
                    token0 = console.peth.call_contract(
                        pair, "token0()->(address)", silent=True
                    )
                    token1 = console.peth.call_contract(
                        pair, "token1()->(address)", silent=True
                    )

                    if token0 and token1:
                        symbol0 = (
                            console.peth.call_contract(
                                token0, "symbol()->(string)", silent=True
                            )
                            or "???"
                        )
                        symbol1 = (
                            console.peth.call_contract(
                                token1, "symbol()->(string)", silent=True
                            )
                            or "???"
                        )
                        click.echo(f"     {symbol0}/{symbol1}")
                except Exception:
                    pass

            except Exception as e:
                click.echo(f"[{i}] Error: {e}")

        if end < total_pairs:
            click.echo(f"\nUse --start {end} to see more pairs")

    except Exception as e:
        click.echo(f"Error accessing factory: {e}", err=True)


@command_click(name="oracle")
@click.argument("addresses", nargs=-1, required=True)
@click.option("--history", "-h", type=int, help="Show last N price updates")
@click.pass_context
def oracle_click(ctx, addresses, history):
    """
    Print ChainLink oracle aggregator information.

    Examples:
        oracle 0x123...                      # Single oracle
        oracle 0x123... 0x456...             # Multiple oracles
        oracle 0x123... --history 10         # Show price history
    """
    console = ctx.obj

    for i, address in enumerate(addresses):
        if len(addresses) > 1:
            click.echo(f"\n---- [{i+1}] {address} ----")

        addr = console.web3.to_checksum_address(address)

        try:
            # Check if it's a proxy
            aggr = console.peth.call_contract(
                addr, "aggregator()->(address)", silent=True
            )
            if aggr:
                click.echo(f"Aggregator: {aggr}")
                proxy_owner = console.peth.call_contract(
                    addr, "owner()->(address)", silent=True
                )
                if proxy_owner:
                    click.echo(f"Proxy Owner: {proxy_owner}")
            else:
                aggr = addr

            # Get aggregator info
            aggr_owner = console.peth.call_contract(
                aggr, "owner()->(address)", silent=True
            )
            if aggr_owner:
                click.echo(f"Aggregator Owner: {aggr_owner}")

            version = console.peth.call_contract(
                aggr, "version()->(uint256)", silent=True
            )
            if version is not None:
                click.echo(f"Version: {version}")

            description = console.peth.call_contract(
                aggr, "description()->(string)", silent=True
            )
            if description:
                click.echo(f"Description: {description}")

            decimals = console.peth.call_contract(
                aggr, "decimals()->(uint8)", silent=True
            )
            if decimals is not None:
                click.echo(f"Decimals: {decimals}")

                # Get latest answer
                latest = console.peth.call_contract(
                    aggr, "latestAnswer()->(int256)", silent=True
                )
                if latest is not None:
                    click.echo(f"Latest Answer: {latest} ({latest/(10**decimals):.2f})")

                # Get min/max
                try:
                    max_answer = console.peth.call_contract(
                        aggr, "maxAnswer()->(int192)", silent=True
                    )
                    if max_answer is not None:
                        click.echo(
                            f"Max Answer: {max_answer} ({max_answer/(10**decimals):.2f})"
                        )

                    min_answer = console.peth.call_contract(
                        aggr, "minAnswer()->(int192)", silent=True
                    )
                    if min_answer is not None:
                        click.echo(
                            f"Min Answer: {min_answer} ({min_answer/(10**decimals):.2f})"
                        )
                except Exception:
                    pass

                # Show history if requested
                if history:
                    try:
                        latest_round = console.peth.call_contract(
                            aggr, "latestRound()->(uint256)", silent=True
                        )
                        if latest_round:
                            click.echo(f"\nLast {history} rounds:")
                            for j in range(min(history, latest_round)):
                                round_id = latest_round - j
                                round_data = console.peth.call_contract(
                                    aggr,
                                    "getRoundData(uint80)->(uint80,int256,uint256,uint256,uint80)",
                                    [round_id],
                                    silent=True,
                                )
                                if round_data:
                                    _, answer, started_at, updated_at, _ = round_data
                                    click.echo(
                                        f"  Round {round_id}: {answer/(10**decimals):.2f} "
                                        f"(updated: {updated_at})"
                                    )
                    except Exception:
                        pass

            # Get transmitters
            try:
                transmitters = console.peth.call_contract(
                    aggr, "transmitters()->(address[])", silent=True
                )
                if transmitters:
                    click.echo(f"\n{len(transmitters)} Transmitters:")
                    for t_addr in transmitters:
                        click.echo(f"  {t_addr}")
            except Exception:
                pass

        except Exception as e:
            click.echo(f"Error reading oracle data: {e}", err=True)
