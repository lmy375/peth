"""Tests for Ethereum blockchain commands."""

import json
from unittest.mock import Mock, mock_open, patch

from hexbytes import HexBytes
from web3 import Web3

from peth.commands.eth import (
    address_click,
    blocks_click,
    call_click,
    estimate_gas_click,
    eth_call_click,
    log_click,
    rpc_call_click,
    run_click,
    send_tx_click,
    storage_click,
    tx_raw_click,
)

from .base import TEST_ADDRESS, TEST_ADDRESS2, TEST_CALLDATA, CommandTestBase


class TestEthCommands(CommandTestBase):
    """Test Ethereum commands."""

    def test_eth_call_basic(self, console):
        """Test eth_call command."""
        console.web3.eth.call = Mock(
            return_value=HexBytes(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            )
        )

        result = self.invoke_command(
            console, eth_call_click, [TEST_ADDRESS, TEST_CALLDATA]
        )

        self.assert_success(result)
        assert "Returns:" in result.output
        # The output doesn't include "0x" prefix when using hex()
        assert (
            "0000000000000000000000000000000000000000000000000000000000000001"
            in result.output
        )

    def test_eth_call_with_sender_value(self, console):
        """Test eth_call with sender and value."""
        console.web3.eth.call = Mock(return_value=HexBytes("0x01"))

        result = self.invoke_command(
            console,
            eth_call_click,
            [TEST_ADDRESS, TEST_CALLDATA, TEST_ADDRESS2, "1000"],
        )

        self.assert_success(result)
        console.web3.eth.call.assert_called_once()
        call_args = console.web3.eth.call.call_args[0][0]
        assert call_args["from"] == Web3.to_checksum_address(TEST_ADDRESS2)
        assert call_args["value"] == 1000

    def test_eth_call_error(self, console):
        """Test eth_call with error."""
        console.web3.eth.call = Mock(side_effect=Exception("execution reverted"))

        result = self.invoke_command(
            console, eth_call_click, [TEST_ADDRESS, TEST_CALLDATA]
        )

        self.assert_success(result)
        assert "Error:" in result.output
        assert "execution reverted" in result.output

    def test_estimate_gas_basic(self, console):
        """Test estimate_gas command."""
        console.web3.eth.estimate_gas = Mock(return_value=21000)

        result = self.invoke_command(
            console, estimate_gas_click, [TEST_ADDRESS, TEST_CALLDATA]
        )

        self.assert_success(result)
        assert "Gas: 21000" in result.output

    def test_call_basic(self, console):
        """Test call command."""
        console.peth.call_contract = Mock(return_value="1000000")
        console._parse_args = Mock(return_value=[TEST_ADDRESS2])

        result = self.invoke_command(
            console, call_click, [TEST_ADDRESS, "balanceOf", TEST_ADDRESS2]
        )

        self.assert_success(result)
        assert "1000000" in result.output
        console.peth.call_contract.assert_called_once_with(
            TEST_ADDRESS, "balanceOf", [TEST_ADDRESS2], silent=False
        )

    def test_rpc_call_basic(self, console):
        """Test rpc_call command."""
        console.peth.rpc_call = Mock(return_value={"result": "0x1"})

        result = self.invoke_command(console, rpc_call_click, ["eth_blockNumber"])

        self.assert_success(result)
        parsed = json.loads(result.output)
        assert parsed["result"] == "0x1"

    def test_rpc_call_with_args(self, console):
        """Test rpc_call with arguments."""
        console.peth.rpc_call = Mock(return_value={"balance": "1000"})

        result = self.invoke_command(
            console, rpc_call_click, ["eth_getBalance", TEST_ADDRESS, "latest"]
        )

        self.assert_success(result)
        console.peth.rpc_call.assert_called_once_with(
            "eth_getBalance", [TEST_ADDRESS, "latest"]
        )

    def test_tx_raw_basic(self, console):
        """Test tx_raw command."""
        tx_data = {
            "hash": "0xabc",
            "from": TEST_ADDRESS,
            "to": TEST_ADDRESS2,
            "value": 1000,
        }
        receipt_data = {"status": 1, "gasUsed": 21000}

        console.web3.eth.get_transaction = Mock(return_value=tx_data)
        console.web3.eth.get_transaction_receipt = Mock(return_value=receipt_data)
        console._print_json = Mock()

        result = self.invoke_command(console, tx_raw_click, ["0xabc"])

        self.assert_success(result)
        assert console._print_json.call_count == 2
        assert "Transaction:" in result.output
        assert "Receipt:" in result.output

    def test_address_basic(self, console):
        """Test address command."""
        console.web3.eth.get_balance = Mock(return_value=10**18)  # 1 ETH
        console.web3.eth.get_transaction_count = Mock(return_value=5)
        console.web3.eth.get_code = Mock(return_value=HexBytes("0x"))

        result = self.invoke_command(console, address_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Balance: 1000000000000000000 Wei (1.0000 Ether)" in result.output
        assert "Nonce: 5" in result.output
        assert "Code Size: 0 bytes" in result.output

    def test_address_with_code(self, console):
        """Test address command with --code flag."""
        code = HexBytes("0x608060405260043610603f")
        console.web3.eth.get_balance = Mock(return_value=0)
        console.web3.eth.get_transaction_count = Mock(return_value=0)
        console.web3.eth.get_code = Mock(return_value=code)
        console.web3.keccak = Mock(return_value=HexBytes("0x" + "a" * 64))

        result = self.invoke_command(console, address_click, [TEST_ADDRESS, "--code"])

        self.assert_success(result)
        assert f"Code Size: {len(code)} bytes" in result.output
        assert "Code Hash:" in result.output

    def test_storage_single_slot(self, console):
        """Test storage command for single slot."""
        console.web3.eth.get_storage_at = Mock(
            return_value=HexBytes(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            )
        )

        result = self.invoke_command(console, storage_click, [TEST_ADDRESS, "0"])

        self.assert_success(result)
        assert "0x0 :" in result.output
        console.web3.eth.get_storage_at.assert_called_once_with(TEST_ADDRESS, 0)

    def test_storage_range(self, console):
        """Test storage command with default range."""
        console.web3.eth.get_storage_at = Mock(return_value=HexBytes("0x00"))

        result = self.invoke_command(console, storage_click, [TEST_ADDRESS])

        self.assert_success(result)
        # Should show 16 slots by default
        assert console.web3.eth.get_storage_at.call_count == 16

    def test_storage_custom_range(self, console):
        """Test storage with custom range."""
        console.web3.eth.get_storage_at = Mock(return_value=HexBytes("0x00"))

        result = self.invoke_command(
            console, storage_click, [TEST_ADDRESS, "--range", "5"]
        )

        self.assert_success(result)
        assert console.web3.eth.get_storage_at.call_count == 5

    def test_send_tx_no_signer(self, console):
        """Test send_tx without signer set."""
        console.peth.signer = None

        result = self.invoke_command(console, send_tx_click, ["0x00"])

        self.assert_success(result)
        assert "Use 'signer' command to set your key first" in result.output

    def test_send_tx_with_confirmation(self, console):
        """Test send_tx with user confirmation."""
        console.peth.signer = Mock()
        console._parse_args = Mock(return_value=["0x00"])

        mock_tx = {"from": TEST_ADDRESS, "to": TEST_ADDRESS2, "data": "0x00"}
        mock_signed = Mock()
        mock_signed.hash.hex.return_value = "0xabc"
        mock_signed.rawTransaction = HexBytes("0xdef")
        mock_signed.r = 1
        mock_signed.s = 2
        mock_signed.v = 27

        console.peth.send_transaction = Mock(return_value=(mock_tx, mock_signed))
        console.peth.web3.eth.block_number = 1000
        console._print_json = Mock()

        # Simulate user not confirming
        with patch("click.confirm", return_value=False):
            result = self.invoke_command(console, send_tx_click, ["0x00"])

            self.assert_success(result)
            assert "Cancelled" in result.output

    def test_log_basic(self, console):
        """Test log command."""
        mock_logs = [
            Mock(
                removed=False,
                transactionHash=HexBytes("0xabc"),
                address=TEST_ADDRESS,
                topics=[HexBytes("0x123")],
                data="0x456",
            )
        ]
        console.peth.get_logs = Mock(return_value=mock_logs)

        result = self.invoke_command(console, log_click, [])

        self.assert_success(result)
        assert "txid 0abc" in result.output
        assert f"address {TEST_ADDRESS}" in result.output
        assert "topic[0] 0123" in result.output

    def test_log_with_filters(self, console):
        """Test log with address and topic filters."""
        console.peth.get_logs = Mock(return_value=[])

        result = self.invoke_command(
            console,
            log_click,
            ["--address", TEST_ADDRESS, "--topic0", "0xddf252ad", "--blocks", "1000"],
        )

        self.assert_success(result)
        console.peth.get_logs.assert_called_once()
        args = console.peth.get_logs.call_args[0]
        assert args[0] == TEST_ADDRESS
        # The command pads topics to 64 characters
        assert (
            args[1][0]
            == "0x00000000000000000000000000000000000000000000000000000000ddf252ad"
        )
        assert console.peth.get_logs.call_args[1]["step"] == 1000

    def test_blocks_command(self, console):
        """Test blocks command."""
        finalized = Mock(number=1000, timestamp=100)
        safe = Mock(number=1010, timestamp=110)
        latest = Mock(number=1020, timestamp=120)

        console._get_block = Mock(side_effect=[finalized, safe, latest])
        console._print_block = Mock()

        result = self.invoke_command(console, blocks_click, [])

        self.assert_success(result)
        assert console._print_block.call_count == 3
        assert "Block rate:" in result.output
        assert "Safe gap: 10 blocks" in result.output
        assert "Finalized gap: 20 blocks" in result.output

    def test_run_solidity(self, console):
        """Test run command with Solidity file."""
        console.peth.run_solidity = Mock(return_value="0x123")

        # Patch specific methods instead of builtins.open
        with patch("os.path.exists", return_value=True):
            import peth.commands.eth

            with patch.object(
                peth.commands.eth, "open", mock_open(read_data="contract Test {}")
            ):
                result = self.invoke_command(console, run_click, ["test.sol"])

                self.assert_success(result)
                assert "0x123" in result.output
                console.peth.run_solidity.assert_called_once()

    def test_run_invalid_file(self, console):
        """Test run with non-.sol file."""
        result = self.invoke_command(console, run_click, ["test.txt"])

        self.assert_success(result)
        assert ".sol file needed" in result.output

    def test_run_nonexistent_file(self, console):
        """Test run with nonexistent file."""
        with patch("os.path.exists", return_value=False):
            result = self.invoke_command(console, run_click, ["test.sol"])

            self.assert_success(result)
            assert "not exists" in result.output
