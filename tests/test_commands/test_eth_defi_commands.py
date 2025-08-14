"""Tests for DeFi and protocol-specific commands."""

from unittest.mock import Mock

from hexbytes import HexBytes

from peth.commands.eth_defi import (
    erc20_click,
    factory_click,
    oracle_click,
    owner_click,
    pair_click,
    proxy_all_click,
    proxy_click,
    safe_click,
    timelock_click,
    view_click,
)

from .base import TEST_ADDRESS, TEST_ADDRESS2, CommandTestBase


class TestEthDeFiCommands(CommandTestBase):
    """Test DeFi and protocol commands."""

    def test_view_simple(self, console):
        """Test view command for simple property."""
        console.peth.get_view_value = Mock(return_value=TEST_ADDRESS)

        result = self.invoke_command(console, view_click, [TEST_ADDRESS, "owner"])

        self.assert_success(result)
        assert TEST_ADDRESS in result.output
        console.peth.get_view_value.assert_called_once_with(TEST_ADDRESS, "owner", None)

    def test_view_with_type(self, console):
        """Test view with explicit type."""
        console.peth.get_view_value = Mock(return_value="MyToken")

        result = self.invoke_command(
            console, view_click, [TEST_ADDRESS, "name", "string"]
        )

        self.assert_success(result)
        assert "MyToken" in result.output
        console.peth.get_view_value.assert_called_once_with(
            TEST_ADDRESS, "name", "string"
        )

    def test_view_array(self, console):
        """Test view for array-like property."""
        console.peth.call_contract = Mock(
            side_effect=[
                TEST_ADDRESS,  # First element
                TEST_ADDRESS2,  # Second element
                None,  # Stop condition
            ]
        )

        result = self.invoke_command(
            console, view_click, [TEST_ADDRESS, "owners", "address", "10"]
        )

        self.assert_success(result)
        assert f"[0]\t{TEST_ADDRESS}" in result.output
        assert f"[1]\t{TEST_ADDRESS2}" in result.output
        assert "None found. Stopping." in result.output

    def test_view_array_with_length_method(self, console):
        """Test view array with length from another method."""
        console.peth.get_view_value = Mock(return_value=2)
        console.peth.call_contract = Mock(side_effect=[TEST_ADDRESS, TEST_ADDRESS2])

        result = self.invoke_command(
            console, view_click, [TEST_ADDRESS, "owners", "address", "ownersLength"]
        )

        self.assert_success(result)
        assert console.peth.get_view_value.call_count == 1
        assert console.peth.call_contract.call_count == 2

    def test_erc20_info(self, console):
        """Test erc20 command showing token info."""
        console._parse_args = Mock(return_value=TEST_ADDRESS)
        console.peth.call_contract = Mock(
            side_effect=[
                "MyToken",  # name
                "MTK",  # symbol
                18,  # decimals
                10**9,  # totalSupply
            ]
        )

        result = self.invoke_command(console, erc20_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Name: MyToken" in result.output
        assert "Symbol: MTK" in result.output
        assert "Decimals: 18" in result.output
        assert "Total Supply: 1000000000" in result.output

    def test_erc20_function_call(self, console):
        """Test erc20 with function call."""
        console.peth.call_contract = Mock(return_value=1000000)

        result = self.invoke_command(
            console, erc20_click, [TEST_ADDRESS, "balanceOf", TEST_ADDRESS2]
        )

        self.assert_success(result)
        assert "1000000" in result.output

    def test_erc20_invalid_function(self, console):
        """Test erc20 with invalid function."""
        result = self.invoke_command(
            console, erc20_click, [TEST_ADDRESS, "invalidFunc", TEST_ADDRESS2]
        )

        self.assert_success(result)
        assert "not a valid ERC20 method" in result.output

    def test_proxy_erc1967(self, console):
        """Test proxy command for ERC1967 proxy."""
        # Mock storage slots
        impl_slot = HexBytes("0x" + "0" * 24 + TEST_ADDRESS[2:])
        admin_slot = HexBytes("0x" + "0" * 24 + TEST_ADDRESS2[2:])
        beacon_slot = HexBytes("0x" + "0" * 64)

        console.web3.eth.get_storage_at = Mock(
            side_effect=[
                impl_slot,  # Implementation
                admin_slot,  # Admin
                beacon_slot,  # Beacon
                HexBytes("0x" + "0" * 64),  # Rollback
            ]
        )
        console._get_full_name = Mock(
            side_effect=[
                f"{TEST_ADDRESS} Implementation",
                f"{TEST_ADDRESS2} ProxyAdmin",
                "0x0000000000000000000000000000000000000000 ",
            ]
        )

        result = self.invoke_command(console, proxy_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "is an ERC-1967 Proxy" in result.output
        assert "Implementation:" in result.output
        assert "Admin:" in result.output

    def test_proxy_not_erc1967(self, console):
        """Test proxy command for non-ERC1967 proxy."""
        # All slots are zero
        console.web3.eth.get_storage_at = Mock(return_value=HexBytes("0x" + "0" * 64))
        console._get_full_name = Mock(
            return_value="0x0000000000000000000000000000000000000000 "
        )

        result = self.invoke_command(console, proxy_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "may not be an ERC-1967 Proxy" in result.output

    def test_proxy_all_command(self, console):
        """Test proxy_all command."""
        impl_slot = HexBytes("0x" + "0" * 24 + TEST_ADDRESS2[2:])
        zero_slot = HexBytes("0x" + "0" * 64)

        console.web3.eth.get_storage_at = Mock(
            side_effect=[
                impl_slot,  # First address has implementation
                zero_slot,  # Second address is not a proxy
            ]
        )
        console.peth.scan.get_contract_name = Mock(return_value="MyProxy")

        result = self.invoke_command(
            console, proxy_all_click, [TEST_ADDRESS, TEST_ADDRESS2]
        )

        self.assert_success(result)
        # Should only show the proxy
        assert f"Proxy MyProxy {TEST_ADDRESS} impl {TEST_ADDRESS2}" in result.output

    def test_owner_success(self, console):
        """Test owner command success."""
        console.peth.call_contract = Mock(return_value=TEST_ADDRESS2)
        console._get_full_name = Mock(return_value=f"{TEST_ADDRESS2} OwnerName")

        result = self.invoke_command(console, owner_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert f"Owner: {TEST_ADDRESS2} OwnerName" in result.output

    def test_owner_not_ownable(self, console):
        """Test owner command on non-Ownable contract."""
        console.peth.call_contract = Mock(side_effect=Exception("No owner function"))

        result = self.invoke_command(console, owner_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Ensure the address is an Ownable contract" in result.output

    def test_safe_command(self, console):
        """Test safe command for Gnosis Safe."""
        console.peth.call_contract = Mock(
            side_effect=[
                "1.3.0",  # VERSION
                2,  # threshold
                [TEST_ADDRESS, TEST_ADDRESS2],  # owners
                TEST_ADDRESS2,  # masterCopy
                [],  # modules (empty)
            ]
        )
        console._get_full_name = Mock(return_value=f"{TEST_ADDRESS} Owner")
        console.web3.eth.get_storage_at = Mock(return_value=HexBytes("0x" + "0" * 64))

        result = self.invoke_command(console, safe_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Version: 1.3.0" in result.output
        assert "Policy: 2/2" in result.output
        assert "Owners:" in result.output

    def test_safe_with_modules(self, console):
        """Test safe command with modules option."""
        console.peth.call_contract = Mock(
            side_effect=[
                "1.3.0",
                2,
                [TEST_ADDRESS],
                None,  # masterCopy fails
                ([TEST_ADDRESS2], "0x01"),  # getModulesPaginated
            ]
        )
        console._get_full_name = Mock(return_value="Module")
        console.web3.eth.get_storage_at = Mock(return_value=HexBytes("0x" + "0" * 64))

        result = self.invoke_command(console, safe_click, [TEST_ADDRESS, "--modules"])

        self.assert_success(result)
        assert "Modules:" in result.output

    def test_timelock_command(self, console):
        """Test timelock command."""
        console.peth.call_contract = Mock(
            side_effect=[
                3600,  # getMinDelay - 1 hour
                None,  # MINIMUM_DELAY fails
                7200,  # MAXIMUM_DELAY - 2 hours
                1800,  # delay - 30 minutes
                TEST_ADDRESS2,  # admin
            ]
        )
        console._get_full_name = Mock(return_value=f"{TEST_ADDRESS2} Admin")

        result = self.invoke_command(console, timelock_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Min Delay: 3600s = 1.00h" in result.output
        assert "Max Delay: 7200s = 2.00h" in result.output
        assert "Current Delay: 1800s = 0.50h" in result.output
        assert f"Admin: {TEST_ADDRESS2} Admin" in result.output

    def test_pair_by_address(self, console):
        """Test pair command with pair address."""
        console.peth.call_contract = Mock(
            side_effect=[
                TEST_ADDRESS,  # token0
                TEST_ADDRESS2,  # token1
                "WETH",  # token0 symbol
                18,  # token0 decimals
                "USDC",  # token1 symbol
                6,  # token1 decimals
                10**20,  # token0 balance in pair
                10**10,  # token1 balance in pair
                None,  # fee (V2)
            ]
        )

        result = self.invoke_command(console, pair_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "WETH" in result.output
        assert "USDC" in result.output
        assert "Reserves:" in result.output
        assert "V2 Price:" in result.output

    def test_pair_find_from_tokens(self, console):
        """Test pair command finding pair from tokens."""
        pair_address = "0x" + "c" * 40
        console.peth.chain = "eth"
        console.peth.call_contract = Mock(
            side_effect=[
                pair_address,  # getPair result
                "WETH",  # token0 symbol
                18,  # token0 decimals
                "USDC",  # token1 symbol
                6,  # token1 decimals
                10**20,  # reserves
                10**10,
                3000,  # V3 fee
            ]
        )

        result = self.invoke_command(console, pair_click, [TEST_ADDRESS, TEST_ADDRESS2])

        self.assert_success(result)
        assert f"Token Pair: {pair_address}" in result.output
        assert "V3 Fee: 0.30%" in result.output

    def test_factory_command(self, console):
        """Test factory command."""
        pair1 = "0x" + "a" * 40
        pair2 = "0x" + "b" * 40

        console.peth.call_contract = Mock(
            side_effect=[
                100,  # allPairsLength
                pair1,  # allPairs(0)
                TEST_ADDRESS,  # token0 of pair1
                TEST_ADDRESS2,  # token1 of pair1
                "WETH",  # symbol0
                "USDC",  # symbol1
                pair2,  # allPairs(1)
                None,  # Error getting tokens
            ]
        )

        result = self.invoke_command(
            console, factory_click, [TEST_ADDRESS, "--limit", "2"]
        )

        self.assert_success(result)
        assert "100 total pairs found" in result.output
        assert f"[0] {pair1}" in result.output
        assert "WETH/USDC" in result.output
        assert f"[1] {pair2}" in result.output

    def test_oracle_chainlink(self, console):
        """Test oracle command for ChainLink aggregator."""
        console.peth.call_contract = Mock(
            side_effect=[
                TEST_ADDRESS2,  # aggregator (proxy)
                TEST_ADDRESS,  # proxy owner
                TEST_ADDRESS,  # aggregator owner
                8,  # version
                "ETH / USD",  # description
                8,  # decimals
                300000000000,  # latestAnswer (3000.00)
                400000000000,  # maxAnswer
                200000000000,  # minAnswer
                [TEST_ADDRESS, TEST_ADDRESS2],  # transmitters
            ]
        )

        result = self.invoke_command(console, oracle_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Aggregator:" in result.output
        assert "Description: ETH / USD" in result.output
        assert "Latest Answer: 300000000000 (3000.00)" in result.output
        assert "2 Transmitters:" in result.output

    def test_oracle_with_history(self, console):
        """Test oracle command with price history."""
        console.peth.call_contract = Mock(
            side_effect=[
                None,  # No proxy
                None,  # owner
                8,  # version
                "ETH / USD",  # description
                8,  # decimals
                300000000000,  # latestAnswer
                None,  # maxAnswer fails
                None,  # minAnswer fails
                100,  # latestRound
                # getRoundData for 3 rounds
                (100, 300000000000, 1000, 1001, 100),
                (99, 299900000000, 900, 901, 99),
                (98, 299800000000, 800, 801, 98),
                [],  # No transmitters
            ]
        )

        result = self.invoke_command(
            console, oracle_click, [TEST_ADDRESS, "--history", "3"]
        )

        self.assert_success(result)
        assert "Last 3 rounds:" in result.output
        assert "Round 100: 3000.00" in result.output
        assert "Round 99:" in result.output
