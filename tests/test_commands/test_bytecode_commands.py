"""Tests for bytecode-related commands."""

from unittest.mock import MagicMock, Mock, patch

from hexbytes import HexBytes

from peth.commands.bytecode import abi4byte_click, diffasm_click, disasm_click

from .base import TEST_ADDRESS, TEST_ADDRESS2, TEST_BYTECODE, CommandTestBase


class TestBytecodeCommands(CommandTestBase):
    """Test bytecode commands."""

    def test_abi4byte_basic(self, console):
        """Test abi4byte command basic functionality."""
        # Mock selectors
        selectors = [
            HexBytes("0xa9059cbb"),
            HexBytes("0x18160ddd"),
            HexBytes("0x70a08231"),
        ]
        console.peth.get_selectors = Mock(return_value=selectors)

        # Mock selector_to_sigs
        with patch("peth.eth.utils.selector_to_sigs") as mock_sigs:
            mock_sigs.side_effect = [
                ["transfer(address,uint256)"],
                ["totalSupply()"],
                ["balanceOf(address)"],
            ]

            # Mock ABIFunction for totalSupply (no inputs)
            with patch("peth.eth.abi.ABIFunction") as mock_abi_func:
                mock_func = Mock()
                mock_func.inputs = []  # No inputs for totalSupply
                mock_abi_func.return_value = mock_func

                # Mock call_contract for totalSupply to return hex data
                console.peth.call_contract = Mock(
                    return_value=HexBytes("0x" + "0" * 63 + "1")
                )

                # Mock guess_single_calldata
                with patch(
                    "peth.commands.bytecode.guess_single_calldata"
                ) as mock_guess:
                    mock_guess.return_value = ("uint256", 1000000)

                    result = self.invoke_command(
                        console, abi4byte_click, [TEST_ADDRESS]
                    )

                    self.assert_success(result)
                    assert "0xa9059cbb" in result.output
                    assert "transfer(address,uint256)" in result.output
                    assert "0x18160ddd" in result.output
                    assert "totalSupply()" in result.output
                    assert "1000000" in result.output  # totalSupply value

    def test_abi4byte_no_selectors(self, console):
        """Test abi4byte when no selectors found."""
        console.peth.get_selectors = Mock(return_value=[])

        result = self.invoke_command(console, abi4byte_click, [TEST_ADDRESS])

        self.assert_success(result)
        # Should complete without errors even with no selectors

    def test_disasm_basic(self, console):
        """Test disasm command."""
        # Mock get_code
        console.web3.eth.get_code = Mock(return_value=HexBytes(TEST_BYTECODE))

        # Mock Code.disasm
        with patch("peth.eth.bytecode.Code.disasm") as mock_disasm:
            mock_disasm.return_value = "PUSH1 0x80\nPUSH1 0x40\nMSTORE"

            result = self.invoke_command(console, disasm_click, [TEST_ADDRESS])

            self.assert_success(result)
            assert "PUSH1" in result.output
            assert "MSTORE" in result.output
            console.web3.eth.get_code.assert_called_once_with(TEST_ADDRESS)

    def test_disasm_no_code(self, console):
        """Test disasm on EOA (no code)."""
        console.web3.eth.get_code = Mock(return_value=HexBytes("0x"))

        result = self.invoke_command(console, disasm_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "No code found" in result.output

    def test_diffasm_basic(self, console):
        """Test diffasm command."""
        # Mock _get_asm_lines
        asm1 = ["PUSH1 0x80", "PUSH1 0x40", "MSTORE"]
        asm2 = ["PUSH1 0x80", "PUSH1 0x60", "MSTORE", "RETURN"]

        console._get_asm_lines = Mock(side_effect=[asm1, asm2])

        # Mock config object
        mock_config = Mock()
        mock_config.diff_path = "/tmp/peth_diff"
        with patch("peth.core.config.config", mock_config):
            # Mock os.makedirs and file write
            with patch("os.makedirs"):
                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_open.return_value.__enter__.return_value = mock_file

                    result = self.invoke_command(
                        console,
                        diffasm_click,
                        ["eth", TEST_ADDRESS, "bsc", TEST_ADDRESS2],
                    )

                    self.assert_success(result)
                    assert "Written to" in result.output
                    assert ".html" in result.output
                    assert "Similarity:" in result.output

                    # Verify _get_asm_lines was called correctly
                    console._get_asm_lines.assert_any_call("eth", TEST_ADDRESS)
                    console._get_asm_lines.assert_any_call("bsc", TEST_ADDRESS2)

    def test_diffasm_with_output_option(self, console):
        """Test diffasm with custom output filename."""
        asm1 = ["PUSH1 0x80"]
        asm2 = ["PUSH1 0x80"]

        console._get_asm_lines = Mock(side_effect=[asm1, asm2])

        mock_config = Mock()
        mock_config.diff_path = "/tmp/peth_diff"
        with patch("peth.core.config.config", mock_config):
            with patch("os.makedirs"):
                with patch("builtins.open", create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_open.return_value.__enter__.return_value = mock_file

                    result = self.invoke_command(
                        console,
                        diffasm_click,
                        [
                            "eth",
                            TEST_ADDRESS,
                            "eth",
                            TEST_ADDRESS2,
                            "--output",
                            "my_diff",
                        ],
                    )

                    self.assert_success(result)
                    assert "my_diff.html" in result.output
                    assert "Written to" in result.output

    def test_diffasm_with_open_option(self, console):
        """Test diffasm with --open flag."""
        asm1 = ["PUSH1 0x80"]
        asm2 = ["PUSH1 0x80"]

        console._get_asm_lines = Mock(side_effect=[asm1, asm2])
        console.open_cmd = Mock()

        mock_config = Mock()
        mock_config.diff_path = "/tmp/peth_diff"
        with patch("peth.core.config.config", mock_config):
            with patch("os.makedirs"):
                with patch("builtins.open", create=True):
                    result = self.invoke_command(
                        console,
                        diffasm_click,
                        ["eth", TEST_ADDRESS, "eth", TEST_ADDRESS2, "--open"],
                    )

                    self.assert_success(result)
                    # Verify open_cmd was called
                    console.open_cmd.assert_called_once()
                    call_args = console.open_cmd.call_args[0][0]
                    assert ".html" in call_args

    def test_diffasm_identical_code(self, console):
        """Test diffasm with identical bytecode."""
        asm = ["PUSH1 0x80", "PUSH1 0x40", "MSTORE"]

        console._get_asm_lines = Mock(return_value=asm)

        mock_config = Mock()
        mock_config.diff_path = "/tmp/peth_diff"
        with patch("peth.core.config.config", mock_config):
            with patch("os.makedirs"):
                with patch("builtins.open", create=True):
                    result = self.invoke_command(
                        console,
                        diffasm_click,
                        ["eth", TEST_ADDRESS, "eth", TEST_ADDRESS],
                    )

                    self.assert_success(result)
                    assert "Similarity: 100" in result.output

    def test_abi4byte_with_call_error(self, console):
        """Test abi4byte when contract calls fail."""
        selectors = [HexBytes("0x18160ddd")]  # totalSupply
        console.peth.get_selectors = Mock(return_value=selectors)

        with patch("peth.eth.utils.selector_to_sigs") as mock_sigs:
            mock_sigs.return_value = ["totalSupply()"]

            with patch("peth.eth.abi.ABIFunction") as mock_abi_func:
                mock_func = Mock()
                mock_func.inputs = []
                mock_abi_func.return_value = mock_func

                # Mock call_contract returning None (error)
                console.peth.call_contract = Mock(return_value=None)

                result = self.invoke_command(console, abi4byte_click, [TEST_ADDRESS])

                self.assert_success(result)
                assert "0x18160ddd" in result.output
                assert "totalSupply()" in result.output
                # Should handle None return gracefully
