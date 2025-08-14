"""Tests for contract-related commands."""

import json
from unittest.mock import Mock, mock_open, patch

from web3 import Web3

from peth.commands.contract import (
    contract_click,
    debank_click,
    decompile_click,
    deth_click,
    diff_click,
    download_json_click,
    download_source_click,
    graph_click,
    name_click,
    url_click,
    verify_click,
)

from .base import TEST_ADDRESS, TEST_ADDRESS2, TEST_BYTECODE, CommandTestBase


class TestContractCommands(CommandTestBase):
    """Test contract commands."""

    def test_name_valid_address(self, console):
        """Test name command with valid address."""
        console._get_full_name = Mock(return_value=f"{TEST_ADDRESS} MockContract")

        result = self.invoke_command(console, name_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "MockContract" in result.output
        console._get_full_name.assert_called_once_with(TEST_ADDRESS)

    def test_name_invalid_address(self, console):
        """Test name command with invalid address."""
        result = self.invoke_command(console, name_click, ["invalid"])

        self.assert_success(result)
        assert "Invalid address format" in result.output

    def test_contract_verified(self, console):
        """Test contract command with verified contract."""
        contract_info = {
            "ContractName": "TestToken",
            "CompilerVersion": "v0.8.0",
            "ABI": json.dumps(
                [
                    {"type": "function", "name": "totalSupply", "inputs": []},
                    {"type": "fallback"},
                ]
            ),
        }
        console.peth.scan.get_contract_info = Mock(return_value=contract_info)
        console._print_json = Mock()

        # Mock contract calls
        mock_contract = Mock()
        mock_func = Mock()
        mock_func.abi = {"name": "totalSupply", "inputs": []}
        mock_func().call.return_value = 1000000
        mock_contract.all_functions.return_value = [mock_func]
        console.web3.eth.contract = Mock(return_value=mock_contract)

        with patch("peth.eth.sigs.Signature.from_abi") as mock_sig:
            mock_sig.return_value = Mock(inputs=[], __str__=lambda x: "totalSupply()")

            result = self.invoke_command(console, contract_click, [TEST_ADDRESS])

            self.assert_success(result)
            console._print_json.assert_called()
            assert "CALLABLE FUNCTIONS" in result.output
            assert "totalSupply() => 1000000" in result.output

    def test_contract_not_verified(self, console):
        """Test contract command with unverified contract."""
        console.peth.scan.get_contract_info = Mock(return_value=None)

        # Should invoke abi4byte_click
        with patch("peth.commands.contract.abi4byte_click") as mock_abi4byte:
            result = self.invoke_command(console, contract_click, [TEST_ADDRESS])

            self.assert_success(result)
            assert "Contract not verified" in result.output
            # Check that abi4byte was invoked
            assert mock_abi4byte.called

    def test_contract_json_output(self, console):
        """Test contract command with --json flag."""
        contract_info = {"ContractName": "Test", "ABI": "[]"}
        console.peth.scan.get_contract_info = Mock(return_value=contract_info)

        result = self.invoke_command(console, contract_click, [TEST_ADDRESS, "--json"])

        self.assert_success(result)
        # Should output raw JSON
        parsed = json.loads(result.output)
        assert parsed["ContractName"] == "Test"

    def test_graph_single_address(self, console):
        """Test graph command with single address."""
        mock_graph = Mock()
        mock_graph.print_assets = Mock()
        mock_graph.dump = Mock(return_value='{"nodes": [], "edges": []}')
        mock_graph.visit = Mock()

        with patch(
            "peth.commands.contract.ContractRelationGraph", return_value=mock_graph
        ):
            result = self.invoke_command(console, graph_click, [TEST_ADDRESS])

            self.assert_success(result)
            # The command converts to checksum address
            checksum_address = Web3.to_checksum_address(TEST_ADDRESS)
            mock_graph.visit.assert_called_once_with(checksum_address, False)
            mock_graph.print_assets.assert_called_once()
            assert "relation-graph.com" in result.output

    def test_graph_multiple_addresses(self, console):
        """Test graph with multiple addresses."""
        mock_graph = Mock()
        mock_graph.print_assets = Mock()
        mock_graph.dump = Mock(return_value='{"nodes": [], "edges": []}')
        mock_graph.visit = Mock()

        with patch(
            "peth.commands.contract.ContractRelationGraph", return_value=mock_graph
        ):
            result = self.invoke_command(
                console, graph_click, [TEST_ADDRESS, TEST_ADDRESS2]
            )

            self.assert_success(result)
            assert mock_graph.visit.call_count == 2

    def test_graph_with_output(self, console):
        """Test graph with output file."""
        mock_graph = Mock()
        mock_graph.print_assets = Mock()
        mock_graph.dump = Mock(return_value='{"data": "test"}')
        mock_graph.visit = Mock()

        with patch(
            "peth.commands.contract.ContractRelationGraph", return_value=mock_graph
        ):
            with patch("builtins.open", mock_open()) as m:
                result = self.invoke_command(
                    console, graph_click, [TEST_ADDRESS, "--output", "graph.json"]
                )

                self.assert_success(result)
                m.assert_called_once_with("graph.json", "w")
                m().write.assert_called_once_with('{"data": "test"}')
                assert "Graph saved to graph.json" in result.output

    def test_diff_two_addresses(self, console):
        """Test diff with two addresses."""
        console._check_alias = Mock(
            side_effect=[("eth", TEST_ADDRESS), ("bsc", TEST_ADDRESS2)]
        )

        with patch("peth.util.diff.diff_chain_src") as mock_diff:
            result = self.invoke_command(
                console, diff_click, [TEST_ADDRESS, TEST_ADDRESS2]
            )

            self.assert_success(result)
            mock_diff.assert_called_once_with("eth", TEST_ADDRESS, "bsc", TEST_ADDRESS2)

    def test_diff_four_args(self, console):
        """Test diff with chain and address args."""
        with patch("peth.util.diff.diff_chain_src") as mock_diff:
            result = self.invoke_command(
                console, diff_click, ["eth", TEST_ADDRESS, "bsc", TEST_ADDRESS2]
            )

            self.assert_success(result)
            mock_diff.assert_called_once_with("eth", TEST_ADDRESS, "bsc", TEST_ADDRESS2)

    def test_diff_pattern(self, console):
        """Test diff with pattern (uni, sushi, etc)."""
        with patch("peth.util.diff.PATTERNS", {"uni": {}}):
            with patch("peth.util.diff.diff_pattern") as mock_pattern:
                result = self.invoke_command(
                    console, diff_click, ["uni", "bsc", "0", TEST_ADDRESS, "0"]
                )

                self.assert_success(result)
                mock_pattern.assert_called_once_with(
                    "uni", "bsc", None, TEST_ADDRESS, None
                )

    def test_download_json_basic(self, console):
        """Test download_json command."""
        console.peth.scan.download_json = Mock(return_value="/tmp/contract.json")

        result = self.invoke_command(console, download_json_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Downloaded as /tmp/contract.json" in result.output
        console.peth.scan.download_json.assert_called_once_with(TEST_ADDRESS, None)

    def test_download_json_with_output_dir(self, console):
        """Test download_json with output directory."""
        console.peth.scan.download_json = Mock(return_value="/output/contract.json")

        # Mock os.path.join to return expected path
        with patch("os.path.join", side_effect=lambda *args: "/".join(args)):
            result = self.invoke_command(
                console, download_json_click, [TEST_ADDRESS, "myproject"]
            )

            self.assert_success(result)
            # The command should join config.output_path with "myproject"
            console.peth.scan.download_json.assert_called_once()

    def test_download_json_failed(self, console):
        """Test download_json when download fails."""
        console.peth.scan.download_json = Mock(return_value=None)

        result = self.invoke_command(console, download_json_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Nothing downloaded" in result.output

    def test_download_source_basic(self, console):
        """Test download_source command."""
        console.peth.scan.download_source = Mock(
            return_value=["/tmp/Token.sol", "/tmp/IERC20.sol"]
        )

        result = self.invoke_command(console, download_source_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "Downloaded /tmp/Token.sol" in result.output
        assert "Downloaded /tmp/IERC20.sol" in result.output

    def test_verify_exact_match(self, console):
        """Test verify command with exact match."""
        console._get_code = Mock(return_value=TEST_BYTECODE)

        result = self.invoke_command(
            console, verify_click, [TEST_ADDRESS, TEST_ADDRESS]
        )

        self.assert_success(result)
        assert "Exact 100% match" in result.output

    def test_verify_partial_match(self, console):
        """Test verify with partial match."""
        code1 = "0x608060405260043610603f"
        code2 = "0x608060405260043610604f"  # Slightly different

        console._get_code = Mock(side_effect=[code1, code2])
        console._code_to_list = Mock(side_effect=[[code1[:64]], [code2[:64]]])

        # Mock config.diff_path as a property
        from peth.core import config as config_module

        with patch.object(
            config_module.PethConfig,
            "diff_path",
            new_callable=lambda: property(lambda self: "/tmp/diff"),
        ):
            with patch("os.path.exists", return_value=True):
                with patch("os.makedirs"):
                    with patch("builtins.open", mock_open()):
                        result = self.invoke_command(
                            console, verify_click, [TEST_ADDRESS, TEST_ADDRESS2]
                        )

                        self.assert_success(result)
                        assert "Similarity" in result.output
                        assert "Written to" in result.output

    def test_url_address(self, console):
        """Test url command with address."""
        console.peth.get_address_url = Mock(
            return_value="https://etherscan.io/address/0x123"
        )
        console.open_cmd = Mock()

        result = self.invoke_command(console, url_click, [TEST_ADDRESS])

        self.assert_success(result)
        console.open_cmd.assert_called_once_with('"https://etherscan.io/address/0x123"')

    def test_url_transaction(self, console):
        """Test url command with transaction hash."""
        tx_hash = "0x" + "a" * 64
        console.peth.chain = "eth"
        console.open_cmd = Mock()

        result = self.invoke_command(console, url_click, [tx_hash])

        self.assert_success(result)
        # Should use Phalcon for tx
        assert console.open_cmd.call_args[0][0].find("phalcon.blocksec.com") > 0

    def test_decompile_valid_contract(self, console):
        """Test decompile command with valid contract."""
        console.peth.is_contract = Mock(return_value=True)
        console.peth.get_decompile_url = Mock(return_value="https://dedaub.com/...")
        console.open_cmd = Mock()

        result = self.invoke_command(console, decompile_click, [TEST_ADDRESS])

        self.assert_success(result)
        console.open_cmd.assert_called_once_with("https://dedaub.com/...")

    def test_decompile_eoa(self, console):
        """Test decompile with EOA address."""
        console.peth.is_contract = Mock(return_value=False)

        result = self.invoke_command(console, decompile_click, [TEST_ADDRESS])

        self.assert_success(result)
        assert "is an EOA address" in result.output

    def test_deth_command(self, console):
        """Test deth command."""
        console.peth.get_address_url = Mock(
            return_value="https://etherscan.io/address/0x123"
        )
        console.open_cmd = Mock()

        result = self.invoke_command(console, deth_click, [TEST_ADDRESS])

        self.assert_success(result)
        # Should replace .io with .deth.net
        console.open_cmd.assert_called_once()
        assert "deth.net" in console.open_cmd.call_args[0][0]

    def test_debank_command(self, console):
        """Test debank command."""
        console.open_cmd = Mock()

        result = self.invoke_command(console, debank_click, [TEST_ADDRESS])

        self.assert_success(result)
        console.open_cmd.assert_called_once()
        assert "debank.com/profile" in console.open_cmd.call_args[0][0]
        assert TEST_ADDRESS.lower() in console.open_cmd.call_args[0][0]
