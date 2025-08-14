"""
Tests that have no external dependencies and test actual logic.
These tests can run in CI without any external services.
"""

from unittest.mock import Mock, patch

from hexbytes import HexBytes

from peth.commands.abi import abi_encode_click, fourbyte_click
from peth.commands.console import debug_click, py_click, sender_click
from peth.commands.utils import (
    addresses_click,
    int_command_click,
    keccak256_click,
    time_command_click,
    tokens_click,
)

from .base import TEST_ADDRESS, CommandTestBase


class TestNoDependencyCommands(CommandTestBase):
    """Tests for commands that don't require external dependencies."""

    # ===== Pure Utility Functions =====

    def test_keccak256_utf8(self, console):
        """Test keccak256 with UTF-8 encoding - uses real keccak256."""
        result = self.invoke_command(console, keccak256_click, ["hello"])

        self.assert_success(result)
        # This is the actual keccak256 hash of 'hello'
        assert (
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
            in result.output
        )

    def test_keccak256_different_encoding(self, console):
        """Test keccak256 with different encoding."""
        result = self.invoke_command(
            console, keccak256_click, ["hello world", "--encoding", "ascii"]
        )

        self.assert_success(result)
        # Real hash will be calculated
        assert len(result.output.strip()) == 64  # 64 hex chars

    def test_int_conversions(self, console):
        """Test integer conversions - pure logic."""
        # Decimal to hex
        result = self.invoke_command(console, int_command_click, ["12345"])
        self.assert_success(result)
        assert "Value: 12345" in result.output
        assert "Hex: 0x3039" in result.output
        assert "Value/1e18 (Ether): 1.2345e-14" in result.output

        # Hex to decimal
        result = self.invoke_command(console, int_command_click, ["0x3039"])
        self.assert_success(result)
        assert "Value: 12345" in result.output

        # Scientific notation
        result = self.invoke_command(console, int_command_click, ["1e18"])
        self.assert_success(result)
        assert "Value: 1000000000000000000" in result.output
        assert "Value/1e18 (Ether): 1.0" in result.output

    def test_int_with_units(self, console):
        """Test integer conversion with unit display."""
        result = self.invoke_command(
            console, int_command_click, ["1000000000000000000", "--unit", "ether"]
        )
        self.assert_success(result)
        assert "1.0 Ether" in result.output

    def test_time_interval_format(self, console):
        """Test time interval formatting - pure calculation."""
        # 3600 seconds = 1 hour
        result = self.invoke_command(
            console, time_command_click, ["3600", "--format", "interval"]
        )

        self.assert_success(result)
        assert "3600 secs" in result.output
        assert "1.0 hours" in result.output
        assert "0.0 days" in result.output

        # 90000 seconds = 25 hours = 1.04 days
        result = self.invoke_command(
            console, time_command_click, ["90000", "--format", "interval"]
        )

        self.assert_success(result)
        assert "90000 secs" in result.output
        assert "25.0 hours" in result.output
        assert "1.0 days" in result.output

    def test_time_timestamp_conversion(self, console):
        """Test timestamp to datetime conversion."""
        # Unix timestamp for 2024-01-01 00:00:00 UTC
        result = self.invoke_command(console, time_command_click, ["1704067200"])

        self.assert_success(result)
        assert "2024-01-01" in result.output

    # ===== Console State Management (Pure Logic) =====

    def test_debug_toggle(self, console):
        """Test debug command toggling."""
        # Initial state
        console._debug = False

        # Toggle on
        result = self.invoke_command(console, debug_click, [])
        self.assert_success(result)
        assert "debug set to True" in result.output
        assert console._debug is True

        # Toggle off
        result = self.invoke_command(console, debug_click, [])
        self.assert_success(result)
        assert "debug set to False" in result.output
        assert console._debug is False

    def test_sender_validation(self, console):
        """Test sender address validation."""
        # Valid address
        result = self.invoke_command(console, sender_click, [TEST_ADDRESS])
        self.assert_success(result)
        assert "New:" in result.output
        assert TEST_ADDRESS in result.output

        # Invalid address format
        result = self.invoke_command(console, sender_click, ["invalid"])
        self.assert_success(result)  # Command doesn't fail, just prints error
        assert "Invalid address format" in result.output

    def test_py_eval(self, console):
        """Test Python expression evaluation."""
        # The py command evaluates expressions directly, not through console.py
        result = self.invoke_command(console, py_click, ["2 + 2"])

        self.assert_success(result)
        assert "4" in result.output

    # ===== Data Filtering/Search (Pure Logic) =====

    def test_addresses_search_logic(self, console):
        """Test address search filtering logic."""
        with patch("peth.commands.utils.config") as mock_config:
            mock_config.contracts = {
                "USDC": ("eth", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                "WETH": ("eth", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                "USDC_BSC": ("bsc", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
            }

            # Search by name
            result = self.invoke_command(console, addresses_click, ["--search", "USDC"])
            self.assert_success(result)
            # Check header is present
            assert (
                "Name" in result.output
                and "Chain" in result.output
                and "Address" in result.output
            )
            # Check that USDC entries are present
            assert "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" in result.output
            assert "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d" in result.output
            # WETH should not be in output since we're searching for USDC
            assert "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" not in result.output

            # Search by chain
            result = self.invoke_command(console, addresses_click, ["--chain", "bsc"])
            self.assert_success(result)
            assert (
                "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d" in result.output
            )  # BSC USDC
            assert (
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" not in result.output
            )  # ETH USDC filtered out

    def test_tokens_search_logic(self, console):
        """Test token search filtering logic."""
        with patch(
            "peth.commands.utils.config.tokens",
            {
                "eth": [
                    {
                        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "decimals": 6,
                        "symbol": "USDC",
                        "name": "USD Coin",
                        "price": 1.0,
                    },
                    {
                        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                        "decimals": 6,
                        "symbol": "USDT",
                        "name": "Tether USD",
                        "price": 1.0,
                    },
                    {
                        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                        "decimals": 18,
                        "symbol": "WETH",
                        "name": "Wrapped Ether",
                        "price": 3000.0,
                    },
                ]
            },
        ):
            console.peth.chain = "eth"

            # Search for USD tokens
            result = self.invoke_command(console, tokens_click, ["USD"])
            self.assert_success(result)
            assert "USDC" in result.output
            assert "USDT" in result.output
            assert "WETH" not in result.output  # Filtered out

            # Search by address part
            result = self.invoke_command(console, tokens_click, ["0xA0b8"])
            self.assert_success(result)
            assert "USDC" in result.output
            assert "USDT" not in result.output

    # ===== ABI Encoding (Pure Logic with Mocked Dependencies) =====

    def test_abi_selector_calculation(self, console):
        """Test ABI function selector calculation."""
        with patch("peth.commands.abi.ABIFunction") as mock_abi_func_class:
            mock_func = Mock()
            # Actual selector for 'transfer(address,uint256)'
            mock_func.selector = HexBytes("0xa9059cbb")
            mock_abi_func_class.return_value = mock_func

            result = self.invoke_command(
                console,
                abi_encode_click,
                ["transfer(address,uint256)", "--selector-only"],
            )

            self.assert_success(result)
            assert "a9059cbb" in result.output

    def test_fourbyte_selector_format(self, console):
        """Test 4byte command output formatting."""
        mock_db = Mock()
        mock_db.get_sig_from_selector = Mock(
            return_value=["transfer(address,uint256)", "transfer(address,address)"]
        )

        with patch("peth.eth.utils.SelectorDatabase.get", return_value=mock_db):
            result = self.invoke_command(console, fourbyte_click, ["0xa9059cbb"])

            self.assert_success(result)
            # Test output formatting
            assert "transfer(address,uint256)" in result.output
            assert "transfer(address,address)" in result.output

            # Test selector normalization
            mock_db.get_sig_from_selector.assert_called_once_with(
                "0xa9059cbb", False, True
            )
