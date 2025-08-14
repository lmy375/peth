"""Tests for transaction-related commands."""

from unittest.mock import Mock, patch

from hexbytes import HexBytes

from peth.commands.transaction import (
    aml_click,
    evm_trace_call_click,
    evm_trace_tx_click,
    idm_click,
    trace_call_click,
    trace_tx_click,
    tx_click,
    tx_replay_click,
    txs_click,
)

from .base import TEST_ADDRESS, TEST_ADDRESS2, TEST_TX_HASH, CommandTestBase


class TestTransactionCommands(CommandTestBase):
    """Test transaction commands."""

    def test_tx_by_hash(self, console):
        """Test tx command with transaction hash."""
        tx_info = {
            "from": TEST_ADDRESS,
            "to": TEST_ADDRESS2,
            "input": "0xa9059cbb" + "0" * 128,
        }
        receipt = {
            "status": 1,
            "contractAddress": None,
            "logs": [
                Mock(
                    topics=[
                        HexBytes(
                            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        ),
                        HexBytes("0x" + "0" * 24 + TEST_ADDRESS[2:]),
                        HexBytes("0x" + "0" * 24 + TEST_ADDRESS2[2:]),
                    ],
                    data=HexBytes("0x" + "0" * 63 + "1"),
                    address="0x" + "c" * 40,
                )
            ],
        }

        console.web3.eth.get_transaction = Mock(return_value=tx_info)
        console.web3.eth.get_transaction_receipt = Mock(return_value=receipt)
        console._print_decoded_calldata = Mock()
        console.peth.call_contract = Mock(return_value="USDC")

        result = self.invoke_command(console, tx_click, [TEST_TX_HASH])

        self.assert_success(result)
        assert f"From: {TEST_ADDRESS}" in result.output
        assert f"To: {TEST_ADDRESS2}" in result.output
        assert "ERC20 Transfers:" in result.output
        assert "USDC" in result.output
        console._print_decoded_calldata.assert_called_once()

    def test_tx_contract_creation(self, console):
        """Test tx command for contract creation."""
        tx_info = {"from": TEST_ADDRESS, "to": None, "input": "0x608060"}
        receipt = {"status": 1, "contractAddress": TEST_ADDRESS2, "logs": []}

        console.web3.eth.get_transaction = Mock(return_value=tx_info)
        console.web3.eth.get_transaction_receipt = Mock(return_value=receipt)

        result = self.invoke_command(console, tx_click, [TEST_TX_HASH])

        self.assert_success(result)
        assert f"{TEST_ADDRESS} creates contract {TEST_ADDRESS2}" in result.output

    def test_tx_reverted(self, console):
        """Test tx command for reverted transaction."""
        tx_info = {"from": TEST_ADDRESS, "to": TEST_ADDRESS2, "input": "0x"}
        receipt = {"status": 0, "logs": []}

        console.web3.eth.get_transaction = Mock(return_value=tx_info)
        console.web3.eth.get_transaction_receipt = Mock(return_value=receipt)

        result = self.invoke_command(console, tx_click, [TEST_TX_HASH])

        self.assert_success(result)
        assert "Tx reverted" in result.output

    def test_tx_decode_calldata(self, console):
        """Test tx command decoding calldata."""
        console._print_decoded_calldata = Mock()

        # Test with address
        result = self.invoke_command(console, tx_click, [TEST_ADDRESS, "0xa9059cbb"])

        self.assert_success(result)
        console._print_decoded_calldata.assert_called_with(
            "0xa9059cbb", TEST_ADDRESS, None
        )

        # Test with signature
        console._print_decoded_calldata.reset_mock()
        result = self.invoke_command(
            console, tx_click, ["transfer(address,uint256)", "0xa9059cbb"]
        )

        self.assert_success(result)
        console._print_decoded_calldata.assert_called_with(
            "0xa9059cbb", None, "transfer(address,uint256)"
        )

    def test_idm_basic(self, console):
        """Test idm command."""
        txs = [
            {
                "from": TEST_ADDRESS,
                "to": TEST_ADDRESS2,
                "input": "0x48656c6c6f20576f726c64",  # "Hello World"
                "value": "1000000000000000000",
            }
        ]
        console.peth.scan.get_txs_by_account = Mock(return_value=txs)

        result = self.invoke_command(console, idm_click, [TEST_ADDRESS2])

        self.assert_success(result)
        assert "Hacker to" in result.output
        assert "1.0000 ETH" in result.output
        assert "Hello World" in result.output

    def test_idm_with_options(self, console):
        """Test idm with count and order options."""
        console.peth.scan.get_txs_by_account = Mock(return_value=[])

        result = self.invoke_command(
            console, idm_click, [TEST_ADDRESS, "50", "desc", "1000000", "2000000"]
        )

        self.assert_success(result)
        console.peth.scan.get_txs_by_account.assert_called_once_with(
            TEST_ADDRESS, 1000000, 2000000, 50, True
        )

    def test_txs_basic(self, console):
        """Test txs command."""
        txs = [
            {
                "hash": TEST_TX_HASH,
                "blockNumber": "1000000",
                "from": TEST_ADDRESS,
                "to": TEST_ADDRESS2,
                "input": "0xa9059cbb",
                "contractAddress": None,
                "value": "0",
            }
        ]
        console.peth.scan.get_txs_by_account = Mock(return_value=txs)
        console.peth.scan.get_address_name = Mock(return_value="Token")

        result = self.invoke_command(console, txs_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert TEST_TX_HASH in result.output
        assert "Block: 1000000" in result.output
        assert f"{TEST_ADDRESS} -> Token" in result.output

    def test_txs_contract_creation(self, console):
        """Test txs showing contract creation."""
        txs = [
            {
                "hash": TEST_TX_HASH,
                "blockNumber": "1000000",
                "from": TEST_ADDRESS,
                "to": None,
                "input": "0x608060",
                "contractAddress": TEST_ADDRESS2,
                "value": "0",
            }
        ]
        console.peth.scan.get_txs_by_account = Mock(return_value=txs)
        console.peth.scan.get_address_name = Mock(return_value="NewContract")

        result = self.invoke_command(console, txs_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert f"{TEST_ADDRESS} creates contract NewContract" in result.output

    def test_txs_with_full_option(self, console):
        """Test txs with --full option."""
        txs = [
            {
                "hash": TEST_TX_HASH,
                "blockNumber": "1000000",
                "from": TEST_ADDRESS,
                "to": TEST_ADDRESS2,
                "input": "0xa9059cbb" + "0" * 128,
                "contractAddress": None,
                "value": "1000",
            }
        ]
        console.peth.scan.get_txs_by_account = Mock(return_value=txs)
        console.peth.scan.get_address_name = Mock(return_value=TEST_ADDRESS2)
        console._print_decoded_calldata = Mock()

        result = self.invoke_command(console, txs_click, [TEST_ADDRESS, "--full"])

        self.assert_success(result)
        assert "value 1000" in result.output
        console._print_decoded_calldata.assert_called_once()

    def test_aml_basic(self, console):
        """Test aml command."""
        # First TX - regular transfer
        tx1 = {
            "from": TEST_ADDRESS2,
            "to": TEST_ADDRESS,
            "value": "1000000000000000000",
        }
        # Second TX - from Tornado
        tx2 = {"hash": TEST_TX_HASH, "from": "0x" + "d" * 40, "to": TEST_ADDRESS2}

        console.scan.get_first_tx = Mock(
            side_effect=[
                (False, tx1),  # First address
                (True, tx2),  # Second address (internal tx)
                (None, None),  # Stop
            ]
        )
        console.web3.eth.get_transaction = Mock(return_value=tx2)
        console.scan.get_contract_name = Mock(return_value="Tornado.Cash")

        result = self.invoke_command(console, aml_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert f"Start: {TEST_ADDRESS}" in result.output
        assert "sends" in result.output
        assert "1.00000 ETH" in result.output
        assert "Tornado.Cash" in result.output
        assert "Tornado Cash detected" in result.output

    def test_aml_max_depth(self, console):
        """Test aml with max depth limit."""
        tx = {"from": TEST_ADDRESS2, "to": TEST_ADDRESS, "value": "0"}
        console.scan.get_first_tx = Mock(return_value=(False, tx))

        result = self.invoke_command(
            console, aml_click, [TEST_ADDRESS, "--max-depth", "3"]
        )

        self.assert_success(result)
        assert "Reached maximum depth of 3" in result.output

    def test_tx_replay_basic(self, console):
        """Test tx_replay command."""
        tx = {
            "blockNumber": 1000000,
            "to": TEST_ADDRESS2,
            "input": "0xa9059cbb",
            "value": 0,
        }
        console.web3.eth.get_transaction = Mock(return_value=tx)
        console.web3.eth.call = Mock(return_value=HexBytes("0x0001"))

        result = self.invoke_command(console, tx_replay_click, [TEST_TX_HASH])

        self.assert_success(result)
        assert "Replay succeeded" in result.output
        assert "0x0001" in result.output

    def test_tx_replay_with_sender(self, console):
        """Test tx_replay with custom sender."""
        tx = {"blockNumber": 1000000, "to": TEST_ADDRESS2, "input": "0x", "value": 0}
        console.web3.eth.get_transaction = Mock(return_value=tx)
        console.web3.eth.call = Mock(side_effect=Exception("sender check failed"))

        result = self.invoke_command(
            console, tx_replay_click, [TEST_TX_HASH, TEST_ADDRESS]
        )

        self.assert_success(result)
        assert "Replay failed" in result.output
        assert "sender check failed" in result.output

    def test_trace_tx_basic(self, console):
        """Test trace_tx command."""
        mock_trace = Mock()
        mock_trace.print = Mock()

        with patch("peth.core.tracer.GethTracer") as MockTracer:
            mock_tracer = Mock()
            mock_tracer.trace_transaction = Mock(return_value={"result": "trace"})
            MockTracer.return_value = mock_tracer

            with patch("peth.core.tracer.TxTrace", return_value=mock_trace):
                result = self.invoke_command(console, trace_tx_click, [TEST_TX_HASH])

                self.assert_success(result)
                mock_tracer.trace_transaction.assert_called_once_with(TEST_TX_HASH)
                mock_trace.print.assert_called_once()

    def test_trace_call_basic(self, console):
        """Test trace_call command."""
        mock_trace = Mock()
        mock_trace.print = Mock()

        with patch("peth.core.tracer.GethTracer") as MockTracer:
            mock_tracer = Mock()
            mock_tracer.trace_call = Mock(return_value={"result": "trace"})
            MockTracer.return_value = mock_tracer

            with patch("peth.core.tracer.TxTrace", return_value=mock_trace):
                result = self.invoke_command(
                    console, trace_call_click, [TEST_ADDRESS, "0xa9059cbb"]
                )

                self.assert_success(result)
                call_args = mock_tracer.trace_call.call_args[0][0]
                assert call_args["to"] == TEST_ADDRESS
                assert call_args["data"] == "0xa9059cbb"

    def test_evm_trace_tx_basic(self, console):
        """Test evm_trace_tx command."""
        tx = {
            "blockNumber": 1000000,
            "from": TEST_ADDRESS,
            "to": TEST_ADDRESS2,
            "value": 0,
            "input": "0xa9059cbb",
        }
        console.web3.eth.get_transaction = Mock(return_value=tx)

        mock_result = Mock()
        mock_trace = Mock()
        mock_trace.print = Mock()
        mock_result.trace = mock_trace

        with patch("peth.eth.evm.Chain") as MockChain:
            mock_chain = Mock()
            mock_chain.apply_transaction = Mock(return_value=mock_result)
            MockChain.return_value = mock_chain

            with patch("peth.eth.evm.ForkChain"):
                with patch("peth.eth.evm.VM") as MockVM:
                    result = self.invoke_command(
                        console, evm_trace_tx_click, [TEST_TX_HASH]
                    )

                    self.assert_success(result)
                    assert MockVM.trace is True
                    mock_chain.apply_transaction.assert_called_once()
                    mock_trace.print.assert_called_once_with(9)

    def test_evm_trace_tx_with_options(self, console):
        """Test evm_trace_tx with debug and depth options."""
        tx = {
            "blockNumber": 1000000,
            "from": TEST_ADDRESS,
            "to": TEST_ADDRESS2,
            "value": 0,
            "input": "0x",
        }
        console.web3.eth.get_transaction = Mock(return_value=tx)

        mock_result = Mock()
        mock_result.trace.print = Mock()

        with patch("peth.eth.evm.Chain") as MockChain:
            with patch("peth.eth.evm.VM") as MockVM:
                mock_chain = Mock()
                mock_chain.apply_transaction = Mock(return_value=mock_result)
                MockChain.return_value = mock_chain

                result = self.invoke_command(
                    console,
                    evm_trace_tx_click,
                    [TEST_TX_HASH, "--debug", "--depth", "15"],
                )

                self.assert_success(result)
                assert MockChain.debug is True
                assert MockVM.debug is True
                mock_result.trace.print.assert_called_once_with(15)

    def test_evm_trace_call_basic(self, console):
        """Test evm_trace_call command."""
        mock_result = Mock()
        mock_trace = Mock()
        mock_trace.print = Mock()
        mock_result.trace = mock_trace

        with patch("peth.eth.evm.Chain") as MockChain:
            mock_chain = Mock()
            mock_chain.apply_transaction = Mock(return_value=mock_result)
            MockChain.return_value = mock_chain

            with patch("peth.eth.evm.ForkChain"):
                result = self.invoke_command(
                    console, evm_trace_call_click, [TEST_ADDRESS, "0xa9059cbb"]
                )

                self.assert_success(result)
                mock_chain.apply_transaction.assert_called_once()
                # Check transaction was created with correct params
                tx_arg = mock_chain.apply_transaction.call_args[0][0]
                assert tx_arg.to == TEST_ADDRESS
                assert tx_arg.data == HexBytes("0xa9059cbb")
