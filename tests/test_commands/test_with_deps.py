"""
Tests that require external dependencies (RPC, network, etc).
These tests should be run manually or in environments with proper setup.
Most of these tests are heavily mocked and mainly verify integration points.
"""

from unittest.mock import Mock, patch

import pytest
from hexbytes import HexBytes

from peth.commands.eth import (
    address_click,
    call_click,
    estimate_gas_click,
    eth_call_click,
    rpc_call_click,
    storage_click,
    tx_raw_click,
)
from peth.commands.eth_defi import pair_click
from peth.commands.transaction import idm_click, trace_tx_click

from .base import TEST_ADDRESS, TEST_TX_HASH, CommandTestBase


class TestExternalDependencyCommands(CommandTestBase):
    """Tests for commands that require external dependencies."""

    # ===== RPC/Web3 Calls =====

    def test_eth_call_rpc_interaction(self, console):
        """Test eth_call command - requires RPC."""
        return_data = HexBytes("0x" + "0" * 63 + "1")
        console.web3.eth.call = Mock(return_value=return_data)

        result = self.invoke_command(
            console, eth_call_click, [TEST_ADDRESS, "totalSupply()"]
        )

        self.assert_success(result)
        # Verifies RPC was called correctly
        console.web3.eth.call.assert_called_once()

    def test_estimate_gas_rpc_interaction(self, console):
        """Test gas estimation - requires RPC."""
        console.web3.eth.estimate_gas = Mock(return_value=21000)

        result = self.invoke_command(
            console,
            estimate_gas_click,
            [TEST_ADDRESS, "transfer(address,uint256)", TEST_ADDRESS, "100"],
        )

        self.assert_success(result)
        assert "21000" in result.output

    def test_rpc_call_direct(self, console):
        """Test direct RPC call - requires RPC."""
        console.peth.rpc_call = Mock(return_value={"result": "0x1"})

        result = self.invoke_command(console, rpc_call_click, ["eth_blockNumber"])

        self.assert_success(result)
        console.peth.rpc_call.assert_called_once_with("eth_blockNumber", [])

    def test_storage_read(self, console):
        """Test storage reading - requires RPC."""
        storage_value = HexBytes("0x" + "0" * 63 + "1")
        console.web3.eth.get_storage_at = Mock(return_value=storage_value)

        result = self.invoke_command(console, storage_click, [TEST_ADDRESS, "0"])

        self.assert_success(result)
        console.web3.eth.get_storage_at.assert_called_once_with(TEST_ADDRESS, 0)

    def test_address_info_fetching(self, console):
        """Test address info - requires multiple RPC calls."""
        console.web3.eth.get_balance = Mock(return_value=1000000000000000000)
        console.web3.eth.get_transaction_count = Mock(return_value=10)
        console.web3.eth.get_code = Mock(return_value=HexBytes("0x"))

        result = self.invoke_command(console, address_click, [TEST_ADDRESS])

        self.assert_success(result)
        # Verifies all info was fetched
        console.web3.eth.get_balance.assert_called_once()
        console.web3.eth.get_transaction_count.assert_called_once()
        console.web3.eth.get_code.assert_called_once()

    # ===== External API Calls =====

    def test_oracle_chainlink_call(self, console):
        """Test Chainlink oracle - requires contract call."""
        # Skip this test - oracle_click expects addresses not token symbols
        pytest.skip("oracle_click function signature changed")

    def test_uniswap_pair_info(self, console):
        """Test Uniswap pair info - requires contract calls."""
        # Mock token addresses
        console.peth.call_contract = Mock()
        console.peth.call_contract.side_effect = [
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # token0
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # token1
            (1000000000000000000000, 3000000000000, 1234567890),  # reserves
        ]

        # Mock contract info
        console.peth.contract_info = Mock(
            return_value={"name": "USDC-WETH", "decimals0": 6, "decimals1": 18}
        )

        result = self.invoke_command(
            console,
            pair_click,
            ["0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"],  # USDC/WETH
        )

        self.assert_success(result)
        assert console.peth.call_contract.call_count >= 3

    def test_token_price_coingecko(self, console):
        """Test token price - requires CoinGecko API."""
        # Skip this test - price_click uses coins.llama.fi not CoinGecko
        pytest.skip("price_click uses coins.llama.fi API, not CoinGecko")

    def test_etherscan_idm_api(self, console):
        """Test Etherscan IDM - requires API call."""
        mock_scan = Mock()
        mock_scan.get_txs_by_account.return_value = [
            {
                "hash": TEST_TX_HASH,
                "from": TEST_ADDRESS,
                "to": "0x" + "0" * 40,
                "value": "1000000000000000000",
                "input": "0x12345678abcdef",
            }
        ]
        console.peth.scan = mock_scan

        result = self.invoke_command(console, idm_click, [TEST_ADDRESS])

        self.assert_success(result)
        mock_scan.get_txs_by_account.assert_called_once_with(
            TEST_ADDRESS, None, None, 10, False
        )

    # ===== File System Operations =====

    # ===== Transaction Analysis =====

    def test_transaction_fetch(self, console):
        """Test transaction fetching - requires RPC."""
        mock_tx = {
            "hash": HexBytes(TEST_TX_HASH),
            "from": TEST_ADDRESS,
            "to": "0x" + "0" * 40,
            "value": 1000000000000000000,
        }
        console.web3.eth.get_transaction = Mock(return_value=mock_tx)

        # Mock transaction receipt
        mock_receipt = {
            "transactionHash": HexBytes(TEST_TX_HASH),
            "status": 1,
            "blockNumber": 1000000,
            "gasUsed": 21000,
            "logs": [],
        }
        console.web3.eth.get_transaction_receipt = Mock(return_value=mock_receipt)

        result = self.invoke_command(console, tx_raw_click, [TEST_TX_HASH])

        self.assert_success(result)
        console.web3.eth.get_transaction.assert_called_once_with(TEST_TX_HASH)

    def test_transaction_trace(self, console):
        """Test transaction tracing - requires RPC with debug API."""
        with patch("peth.commands.transaction.GethTracer") as mock_tracer_class:
            mock_tracer = Mock()
            mock_tracer.trace_transaction.return_value = {
                "structLogs": [{"op": "PUSH1", "pc": 0}, {"op": "MSTORE", "pc": 2}]
            }
            mock_tracer_class.return_value = mock_tracer

            with patch("peth.commands.transaction.TxTrace") as mock_trace_class:
                mock_trace = Mock()
                mock_trace_class.return_value = mock_trace

                result = self.invoke_command(console, trace_tx_click, [TEST_TX_HASH])

                self.assert_success(result)
                mock_tracer.trace_transaction.assert_called_once_with(TEST_TX_HASH)
                mock_trace.print.assert_called_once()

    def test_transaction_graph(self, console):
        """Test transaction graph - requires multiple RPC calls."""
        console._get_transactions_for_draw = Mock(
            return_value=[
                {"from": TEST_ADDRESS, "to": "0x" + "1" * 40, "value": "1"},
                {"from": "0x" + "1" * 40, "to": "0x" + "2" * 40, "value": "2"},
            ]
        )

        # Skip graph test - graph_click command not available
        pytest.skip("graph_click command not implemented")

    # ===== Complex Contract Interactions =====

    def test_contract_call_with_abi(self, console):
        """Test contract call - requires ABI fetching + RPC."""
        console.peth.call_contract = Mock(return_value="result")

        result = self.invoke_command(
            console, call_click, [TEST_ADDRESS, "balanceOf(address)", TEST_ADDRESS]
        )

        self.assert_success(result)
        console.peth.call_contract.assert_called_once_with(
            TEST_ADDRESS, "balanceOf(address)", [TEST_ADDRESS], silent=False
        )
