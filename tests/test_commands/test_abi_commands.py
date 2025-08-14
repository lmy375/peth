"""Tests for ABI-related commands."""

from unittest.mock import Mock, patch

from hexbytes import HexBytes

from peth.commands.abi import abi_decode_click, abi_encode_click, fourbyte_click

from .base import TEST_ADDRESS, TEST_CALLDATA, CommandTestBase


class TestABICommands(CommandTestBase):
    """Test ABI commands."""

    def test_4byte_search_by_selector(self, console):
        """Test 4byte command with selector search."""
        # Mock the SelectorDatabase
        mock_db = Mock()
        mock_db.get_sig_from_selector = Mock(
            return_value=["transfer(address,uint256)", "transfer(address,address)"]
        )

        with patch("peth.eth.utils.SelectorDatabase.get", return_value=mock_db):
            result = self.invoke_command(console, fourbyte_click, ["0xa9059cbb"])

            self.assert_success(result)
            assert "transfer(address,uint256)" in result.output
            assert "transfer(address,address)" in result.output
            mock_db.get_sig_from_selector.assert_called_once_with(
                "0xa9059cbb", False, True
            )

    def test_4byte_search_by_text(self, console):
        """Test 4byte command with text search."""
        mock_db = Mock()
        mock_db.get_sig_from_text = Mock(
            return_value=[
                ("a9059cbb", ["transfer(address,uint256)"]),
                ("23b872dd", ["transferFrom(address,address,uint256)"]),
            ]
        )

        with patch("peth.eth.utils.SelectorDatabase.get", return_value=mock_db):
            result = self.invoke_command(console, fourbyte_click, ["transfer"])

            self.assert_success(result)
            assert "0xa9059cbb transfer(address,uint256)" in result.output
            assert "2 item(s) found" in result.output
            mock_db.get_sig_from_text.assert_called_once_with("transfer")

    def test_4byte_no_results(self, console):
        """Test 4byte command with no results."""
        mock_db = Mock()
        mock_db.get_sig_from_selector = Mock(return_value=[])

        with patch("peth.eth.utils.SelectorDatabase.get", return_value=mock_db):
            result = self.invoke_command(console, fourbyte_click, ["0x12345678"])

            self.assert_success(result)
            assert "Selector not found" in result.output

    def test_4byte_database_error(self, console):
        """Test 4byte command when database fails to load."""
        with patch(
            "peth.eth.utils.SelectorDatabase.get", side_effect=Exception("DB error")
        ):
            result = self.invoke_command(console, fourbyte_click, ["0xa9059cbb"])

            self.assert_success(result)
            assert "Error loading selector database" in result.output

    def test_abi_encode_basic(self, console):
        """Test abi_encode with basic function call."""
        # Mock ABIFunction
        with patch("peth.commands.abi.ABIFunction") as mock_abi_func_class:
            mock_func = Mock()
            mock_func.encode_input.return_value = HexBytes(TEST_CALLDATA)
            mock_abi_func_class.return_value = mock_func

            result = self.invoke_command(
                console,
                abi_encode_click,
                ["transfer(address,uint256)", TEST_ADDRESS, "100"],
            )

            self.assert_success(result)
            assert TEST_CALLDATA[2:] in result.output  # Remove 0x prefix for comparison
            # Verify ABIFunction was created with correct signature
            mock_abi_func_class.assert_called_once_with("transfer(address,uint256)")
            # Verify encode_input was called with correct params (convert_value converts '100' to int 100)
            mock_func.encode_input.assert_called_once_with([TEST_ADDRESS, 100])

    def test_abi_encode_no_args(self, console):
        """Test abi_encode with no arguments."""
        with patch("peth.commands.abi.ABIFunction") as mock_abi_func_class:
            mock_func = Mock()
            mock_func.selector = HexBytes("0x12345678")
            mock_abi_func_class.return_value = mock_func

            result = self.invoke_command(console, abi_encode_click, ["totalSupply()"])

            self.assert_success(result)
            assert "12345678" in result.output
            mock_abi_func_class.assert_called_once_with("totalSupply()")

    def test_abi_encode_selector_only(self, console):
        """Test abi_encode with --selector-only flag."""
        with patch("peth.commands.abi.ABIFunction") as mock_abi_func_class:
            mock_func = Mock()
            mock_func.selector = HexBytes("0xa9059cbb")
            mock_abi_func_class.return_value = mock_func

            result = self.invoke_command(
                console,
                abi_encode_click,
                ["transfer(address,uint256)", "--selector-only"],
            )

            self.assert_success(result)
            assert "a9059cbb" in result.output
            mock_abi_func_class.assert_called_once_with("transfer(address,uint256)")

    def test_abi_decode_with_signature(self, console):
        """Test abi_decode with known signature."""
        # Mock console._print_decoded_calldata
        console._print_decoded_calldata = Mock()

        result = self.invoke_command(
            console, abi_decode_click, [TEST_CALLDATA, "transfer(address,uint256)"]
        )

        self.assert_success(result)
        # Verify _print_decoded_calldata was called with correct params
        console._print_decoded_calldata.assert_called_once_with(
            TEST_CALLDATA, sig="transfer(address,uint256)"
        )

    def test_abi_decode_auto_detect(self, console):
        """Test abi_decode with automatic signature detection."""
        # Mock console._print_decoded_calldata
        console._print_decoded_calldata = Mock()

        result = self.invoke_command(console, abi_decode_click, [TEST_CALLDATA])

        self.assert_success(result)
        # Verify _print_decoded_calldata was called with correct params
        console._print_decoded_calldata.assert_called_once_with(TEST_CALLDATA, sig=None)

    def test_abi_decode_unknown_selector(self, console):
        """Test abi_decode with unknown selector."""
        unknown_calldata = "0x12345678" + "0" * 64

        # Mock console._print_decoded_calldata
        console._print_decoded_calldata = Mock()

        result = self.invoke_command(console, abi_decode_click, [unknown_calldata])

        self.assert_success(result)
        # Verify _print_decoded_calldata was called
        console._print_decoded_calldata.assert_called_once_with(
            unknown_calldata, sig=None
        )

    def test_abi_decode_invalid_data(self, console):
        """Test abi_decode with invalid data."""
        result = self.invoke_command(console, abi_decode_click, ["invalid_hex_data"])

        # Should handle gracefully
        self.assert_success(result)
        assert "Error" in result.output or "Invalid" in result.output

    def test_abi_encode_with_array(self, console):
        """Test abi_encode with array parameter."""
        with patch("peth.commands.abi.ABIFunction") as mock_abi_func_class:
            mock_func = Mock()
            mock_func.encode_input.return_value = HexBytes("0xabcdef")
            mock_abi_func_class.return_value = mock_func

            result = self.invoke_command(
                console, abi_encode_click, ["setAddresses(address[])", "[0x123,0x456]"]
            )

            self.assert_success(result)
            assert "abcdef" in result.output
