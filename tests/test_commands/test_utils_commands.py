"""Tests for utility commands."""

from unittest.mock import Mock, patch

from peth.commands.utils import (
    addresses_click,
    aes_click,
    brain_wallet_click,
    int_command_click,
    keccak256_click,
    portfolio_click,
    price_click,
    time_command_click,
    tokens_click,
)

from .base import TEST_ADDRESS, CommandTestBase


class TestUtilsCommands(CommandTestBase):
    """Test utility commands."""

    def test_keccak256_utf8(self, console):
        """Test keccak256 with UTF-8 encoding."""
        result = self.invoke_command(console, keccak256_click, ["hello"])

        self.assert_success(result)
        # keccak256('hello') = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        assert (
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
            in result.output
        )

    def test_keccak256_ascii(self, console):
        """Test keccak256 with ASCII encoding."""
        result = self.invoke_command(
            console, keccak256_click, ["hello", "--encoding", "ascii"]
        )

        self.assert_success(result)
        # Same as keccak256('hello')
        assert (
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
            in result.output
        )

    def test_keccak256_long_text(self, console):
        """Test keccak256 with longer text."""
        result = self.invoke_command(console, keccak256_click, ["hello world"])

        self.assert_success(result)
        # Should output hash without 0x prefix
        assert len(result.output.strip()) == 64  # 64 hex chars

    def test_int_decimal(self, console):
        """Test int command with decimal input."""
        result = self.invoke_command(console, int_command_click, ["12345"])

        self.assert_success(result)
        assert "Value: 12345" in result.output
        assert "Hex: 0x3039" in result.output
        assert (
            "Hex(Uint256): 0000000000000000000000000000000000000000000000000000000000003039"
            in result.output
        )

    def test_int_hex(self, console):
        """Test int command with hex input."""
        result = self.invoke_command(console, int_command_click, ["0x3039"])

        self.assert_success(result)
        assert "Value: 12345" in result.output
        assert "Hex: 0x3039" in result.output

    def test_int_negative(self, console):
        """Test int command with negative number."""
        result = self.invoke_command(console, int_command_click, ["--", "-100"])

        self.assert_success(result)
        assert "Value: -100" in result.output
        # The hex output shows negative value
        assert "Hex(Uint256): -" in result.output

    def test_int_invalid(self, console):
        """Test int command with invalid input."""
        result = self.invoke_command(console, int_command_click, ["invalid"])

        # Should fail with ValueError
        assert result.exit_code != 0
        assert result.exception is not None

    def test_time_timestamp_to_date(self, console):
        """Test time command converting timestamp to date."""
        # Unix timestamp for 2024-01-01 00:00:00 UTC
        result = self.invoke_command(console, time_command_click, ["1704067200"])

        self.assert_success(result)
        assert "2024-01-01" in result.output

    def test_time_with_interval_format(self, console):
        """Test time command with interval format."""
        # 3600 seconds = 1 hour
        result = self.invoke_command(
            console, time_command_click, ["3600", "--format", "interval"]
        )

        self.assert_success(result)
        assert "3600 secs" in result.output
        assert "1.0 hours" in result.output
        assert "0.0 days" in result.output

    def test_time_current(self, console):
        """Test time command without arguments (current time)."""
        with patch("peth.commands.utils.time_module.time") as mock_time:
            # Mock current time to specific timestamp
            mock_time.return_value = 1704067200.0  # 2024-01-01 00:00:00 UTC

            result = self.invoke_command(console, time_command_click, [])

            self.assert_success(result)
            assert "Current: 1704067200" in result.output

    def test_addresses_search(self, console):
        """Test addresses command with search."""
        # Mock the config import in the utils module
        with patch("peth.commands.utils.config") as mock_config:
            mock_config.contracts = {
                "USDC": ("eth", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                "WETH": ("eth", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                "USDC_BSC": ("bsc", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
            }

            # Search for USDC
            result = self.invoke_command(console, addresses_click, ["--search", "USDC"])

            self.assert_success(result)
            assert "USDC" in result.output
            assert "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" in result.output
            assert "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d" in result.output

    def test_addresses_all(self, console):
        """Test addresses command showing all."""
        with patch("peth.commands.utils.config") as mock_config:
            mock_config.contracts = {
                "USDC": ("eth", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
            }

            result = self.invoke_command(console, addresses_click, [])

            self.assert_success(result)
            assert "Name" in result.output
            assert "Chain" in result.output
            assert "Address" in result.output
            assert "USDC" in result.output
            assert "eth" in result.output

    def test_price_token(self, console):
        """Test price command for token."""
        mock_response = {
            "market_data": {
                "current_price": {"usd": 3000.50},
                "price_change_percentage_24h": 2.5,
                "market_cap": {"usd": 360000000000},
            }
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response

            result = self.invoke_command(console, price_click, ["ethereum"])

            self.assert_success(result)
            assert "$3000.50" in result.output
            assert "2.50%" in result.output

    def test_price_multiple_tokens(self, console):
        """Test price command with multiple tokens."""
        mock_responses = [
            {
                "market_data": {
                    "current_price": {"usd": 50000},
                    "price_change_percentage_24h": 1.0,
                    "market_cap": {"usd": 1000000000000},
                }
            },
            {
                "market_data": {
                    "current_price": {"usd": 3000},
                    "price_change_percentage_24h": -0.5,
                    "market_cap": {"usd": 360000000000},
                }
            },
        ]

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.side_effect = mock_responses

            result = self.invoke_command(console, price_click, ["bitcoin", "ethereum"])

            self.assert_success(result)
            assert "bitcoin: $50000" in result.output
            assert "1.00%" in result.output
            assert "ethereum: $3000" in result.output
            assert "-0.50%" in result.output

    def test_brain_generate(self, console):
        """Test brain command with password."""
        with patch("peth.eth.utils.keccak256") as mock_keccak:
            # Mock the password hash to return a predictable private key
            mock_keccak.return_value = bytes.fromhex("1" * 64)

            with patch("eth_account.Account.from_key") as mock_from_key:
                mock_account = Mock()
                mock_account.address = TEST_ADDRESS
                mock_account.key.hex.return_value = "0x" + "1" * 64
                mock_from_key.return_value = mock_account

                result = self.invoke_command(
                    console, brain_wallet_click, ["mypassword"]
                )

                self.assert_success(result)
                assert "Private Key:" in result.output
                assert f"Address: {TEST_ADDRESS}" in result.output
                assert "1" * 64 in result.output

    def test_portfolio_address(self, console):
        """Test portfolio command for single address."""
        # Mock _parse_args
        console._parse_args = Mock(return_value=TEST_ADDRESS)

        # Mock get_portfolio
        portfolio_data = {
            TEST_ADDRESS.lower(): [
                {
                    "balance": 1.0,
                    "usd": 1.0,
                    "info": {
                        "name": "Ether",
                        "symbol": "ETH",
                        "address": "0x0000000000000000000000000000000000000000",
                        "decimals": 18,
                    },
                    "price": 1.0,
                },
                {
                    "balance": 1000.0,
                    "usd": 1000.0,
                    "info": {
                        "name": "USD Coin",
                        "symbol": "USDC",
                        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "decimals": 6,
                    },
                    "price": 1.0,
                },
                {
                    "balance": 0.5,
                    "usd": 1500.0,
                    "info": {
                        "name": "Wrapped Ether",
                        "symbol": "WETH",
                        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                        "decimals": 18,
                    },
                    "price": 3000.0,
                },
            ]
        }
        console.peth.get_portfolio = Mock(return_value=portfolio_data)

        result = self.invoke_command(console, portfolio_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Total: $2,501.00" in result.output
        assert "Ether" in result.output
        assert "ETH" in result.output
        assert "USD Coin" in result.output
        assert "USDC" in result.output
        assert "Wrapped Ether" in result.output
        assert "WETH" in result.output

    def test_portfolio_min_value(self, console):
        """Test portfolio command with --min-value option."""
        # Mock _parse_args
        console._parse_args = Mock(return_value=TEST_ADDRESS)

        # Mock get_portfolio with mixed values
        portfolio_data = {
            TEST_ADDRESS.lower(): [
                {
                    "balance": 0.001,
                    "usd": 0.5,
                    "info": {
                        "name": "Small Token",
                        "symbol": "SMALL",
                        "address": "0x111",
                        "decimals": 18,
                    },
                    "price": 500.0,
                },
                {
                    "balance": 1000.0,
                    "usd": 1000.0,
                    "info": {
                        "name": "USD Coin",
                        "symbol": "USDC",
                        "address": "0x222",
                        "decimals": 6,
                    },
                    "price": 1.0,
                },
            ]
        }
        console.peth.get_portfolio = Mock(return_value=portfolio_data)

        result = self.invoke_command(
            console, portfolio_click, [TEST_ADDRESS, "--min-value", "100"]
        )

        self.assert_success(result)
        # Should only show USDC (value >= 100)
        assert "USD Coin" in result.output
        assert "USDC" in result.output
        assert "Small Token" not in result.output
        assert "SMALL" not in result.output

    def test_tokens_show_all(self, console):
        """Test tokens command showing all tokens."""
        with patch(
            "peth.commands.utils.config.tokens",
            {
                "eth": {
                    "USDC": {
                        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "decimals": 6,
                    }
                }
            },
        ):
            result = self.invoke_command(console, tokens_click, [])

            self.assert_success(result)
            assert "All known tokens:" in result.output
            assert "USDC" in result.output
            assert "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" in result.output

    def test_tokens_search(self, console):
        """Test tokens command with search."""
        with patch(
            "peth.commands.utils.config.tokens",
            {
                "eth": {
                    "USDC": {
                        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "decimals": 6,
                    },
                    "USDT": {
                        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                        "decimals": 6,
                    },
                }
            },
        ):
            result = self.invoke_command(console, tokens_click, ["USD"])

            self.assert_success(result)
            assert "USDC" in result.output
            assert "USDT" in result.output
            assert "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" in result.output

    def test_aes_encrypt(self, console):
        """Test aes command encryption."""
        with patch("peth.eth.utils.encrypt_with_aes") as mock_encrypt:
            mock_encrypt.return_value = "encrypted_data"

            result = self.invoke_command(
                console, aes_click, ["enc", "secret message", "mypassword"]
            )

            self.assert_success(result)
            assert "encrypted_data" in result.output
            mock_encrypt.assert_called_once_with("secret message", "mypassword")

    def test_aes_decrypt(self, console):
        """Test aes command decryption."""
        with patch("peth.eth.utils.decrypt_with_aes") as mock_decrypt:
            mock_decrypt.return_value = "decrypted message"

            result = self.invoke_command(
                console, aes_click, ["dec", "encrypted_data", "mypassword"]
            )

            self.assert_success(result)
            assert "decrypted message" in result.output
            mock_decrypt.assert_called_once_with("encrypted_data", "mypassword")

    def test_aes_decrypt_error(self, console):
        """Test aes decryption with wrong password."""
        with patch("peth.eth.utils.decrypt_with_aes") as mock_decrypt:
            mock_decrypt.side_effect = Exception("Invalid padding")

            result = self.invoke_command(
                console, aes_click, ["dec", "encrypted_data", "wrongpassword"]
            )

            self.assert_success(result)
            assert "Error" in result.output
            assert "Invalid padding" in result.output
