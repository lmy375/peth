"""Tests for console-related commands."""

from unittest.mock import Mock, patch

from peth.commands.console import (
    chain_click,
    config_click,
    debug_click,
    exit_click,
    ipython_click,
    open_click,
    py_click,
    sender_click,
    sh_click,
    signer_click,
)

from .base import TEST_ADDRESS, CommandTestBase


class TestConsoleCommands(CommandTestBase):
    """Test console commands."""

    def test_debug_toggle(self, console):
        """Test debug command toggles debug flag."""
        # Initial state
        assert console._debug is False

        # First toggle
        result = self.invoke_command(console, debug_click, [])
        self.assert_success(result)
        assert "debug set to True" in result.output
        assert console._debug is True

        # Second toggle
        result = self.invoke_command(console, debug_click, [])
        self.assert_success(result)
        assert "debug set to False" in result.output
        assert console._debug is False

    def test_chain_show_current(self, console):
        """Test chain command shows current chain info."""
        console.peth.chain = "eth"
        console.peth.rpc_url = "https://eth.rpc"
        console.peth.api_url = "https://api.etherscan.io"
        console.peth.address_url = "https://etherscan.io/address/"
        console.web3.eth.chain_id = 1
        console.web3.eth.block_number = 1000000

        result = self.invoke_command(console, chain_click, [])

        self.assert_success(result)
        assert "Current:" in result.output
        assert "Chain: eth" in result.output
        assert "Chain ID: 1" in result.output
        assert "Block number: 1000000" in result.output
        assert "RPC: https://eth.rpc" in result.output

    def test_chain_switch(self, console):
        """Test switching chains."""
        # Mock Peth.get_or_create
        new_peth = Mock()
        new_peth.chain = "bsc"
        new_peth.rpc_url = "https://bsc.rpc"
        new_peth.web3.eth.chain_id = 56
        new_peth.web3.eth.block_number = 2000000

        with patch("peth.core.peth.Peth.get_or_create", return_value=new_peth):
            with patch("peth.core.config.config.chains", {"eth": {}, "bsc": {}}):
                result = self.invoke_command(console, chain_click, ["bsc"])

                self.assert_success(result)
                assert "Changed:" in result.output
                assert "Chain: bsc" in result.output

    def test_chain_invalid(self, console):
        """Test invalid chain name."""
        with patch("peth.core.config.config.chains", {"eth": {}, "bsc": {}}):
            result = self.invoke_command(console, chain_click, ["invalid"])

            self.assert_success(result)
            assert "Supported chains: eth, bsc" in result.output

    def test_config_show(self, console):
        """Test config command shows configuration."""
        with patch("peth.core.config.config.print_config") as mock_print:
            result = self.invoke_command(console, config_click, [])

            self.assert_success(result)
            mock_print.assert_called_once()

    def test_config_raw(self, console):
        """Test config raw shows raw INI."""
        with patch("peth.core.config.config.print_ini") as mock_print:
            result = self.invoke_command(console, config_click, ["raw"])

            self.assert_success(result)
            mock_print.assert_called_once()

    def test_config_set(self, console):
        """Test config set changes a setting."""
        mock_cfg = Mock()
        with patch("peth.core.config.config.cfg", mock_cfg):
            result = self.invoke_command(
                console, config_click, ["set", "general", "timeout", "30"]
            )

            self.assert_success(result)
            assert "Set [general] timeout = 30" in result.output
            mock_cfg.set.assert_called_once_with("general", "timeout", "30")

    def test_sender_show(self, console):
        """Test sender command shows current sender."""
        console.peth.sender = TEST_ADDRESS

        result = self.invoke_command(console, sender_click, [])

        self.assert_success(result)
        assert f"Current: {TEST_ADDRESS}" in result.output

    def test_sender_set(self, console):
        """Test sender command sets new sender."""
        new_address = "0xabcdef0123456789abcdef0123456789abcdef01"

        result = self.invoke_command(console, sender_click, [new_address])

        self.assert_success(result)
        assert f"New:     {new_address}" in result.output
        assert console.peth.sender == new_address

    def test_sender_invalid(self, console):
        """Test sender with invalid address."""
        result = self.invoke_command(console, sender_click, ["invalid"])

        self.assert_success(result)
        assert "Invalid address format" in result.output

    def test_signer_show_not_set(self, console):
        """Test signer command when no signer set."""
        console.peth.signer = None

        result = self.invoke_command(console, signer_click, [])

        self.assert_success(result)
        assert "Current: Not set" in result.output

    def test_signer_set(self, console):
        """Test setting signer with private key."""
        private_key = "0x" + "1" * 64

        with patch("eth_account.Account.from_key") as mock_from_key:
            mock_signer = Mock()
            mock_signer.address = TEST_ADDRESS
            mock_from_key.return_value = mock_signer

            result = self.invoke_command(console, signer_click, [private_key])

            self.assert_success(result)
            assert f"New:     {TEST_ADDRESS}" in result.output
            assert console.peth.signer == mock_signer

    def test_signer_show_address_only(self, console):
        """Test signer --show-address option."""
        private_key = "0x" + "1" * 64

        with patch("eth_account.Account.from_key") as mock_from_key:
            mock_signer = Mock()
            mock_signer.address = TEST_ADDRESS
            mock_from_key.return_value = mock_signer

            result = self.invoke_command(
                console, signer_click, [private_key, "--show-address"]
            )

            self.assert_success(result)
            assert f"Address: {TEST_ADDRESS}" in result.output
            # Should not set the signer
            assert console.peth.signer is None

    def test_sh_command(self, console):
        """Test sh command runs system commands."""
        with patch("os.system") as mock_system:
            result = self.invoke_command(console, sh_click, ["ls", "-la"])

            self.assert_success(result)
            mock_system.assert_called_once_with("ls -la")

    def test_py_eval(self, console):
        """Test py command evaluates Python expressions."""
        result = self.invoke_command(console, py_click, ["2 + 2"])

        self.assert_success(result)
        assert "4" in result.output

    def test_py_exec(self, console):
        """Test py command with --exec flag."""
        result = self.invoke_command(console, py_click, ['print("hello")', "--exec"])

        self.assert_success(result)
        assert "hello" in result.output

    def test_py_error(self, console):
        """Test py command with error."""
        result = self.invoke_command(console, py_click, ["1/0"])

        self.assert_success(result)
        assert "Error:" in result.output
        assert "division by zero" in result.output

    def test_ipython_available(self, console):
        """Test ipython command when IPython is available."""
        with patch("IPython.embed") as mock_embed:
            result = self.invoke_command(console, ipython_click, [])

            self.assert_success(result)
            mock_embed.assert_called_once_with(colors="Linux")

    def test_ipython_not_available(self, console):
        """Test ipython command when IPython is not installed."""
        with patch("builtins.__import__", side_effect=ImportError):
            result = self.invoke_command(console, ipython_click, [])

            self.assert_success(result)
            assert "IPython not installed" in result.output

    def test_open_command(self, console):
        """Test open command."""
        with patch("os.system") as mock_system:
            result = self.invoke_command(console, open_click, ["https://example.com"])

            self.assert_success(result)
            mock_system.assert_called_once_with("open https://example.com")

    def test_exit_command(self, console):
        """Test exit command."""
        result = self.invoke_command(console, exit_click, [])

        # Exit command returns True to signal exit
        assert result.exit_code == 0
        assert result.return_value is True
        assert "bye!" in result.output

    def test_exit_force(self, console):
        """Test exit --force command."""
        result = self.invoke_command(console, exit_click, ["--force"])

        assert result.exit_code == 0
        assert result.return_value is True
        # Force exit should not print "bye!"
        assert "bye!" not in result.output

    def test_chain_v2_list(self, console):
        """Test chain v2 command lists v2 chains."""
        mock_chains = [
            {"chainid": "1", "chainname": "Ethereum", "status": 1},
            {"chainid": "56", "chainname": "BSC", "status": 1},
            {"chainid": "137", "chainname": "Polygon", "status": 0},
        ]

        with patch("peth.eth.scan.ScanAPI.get_v2_chainlist", return_value=mock_chains):
            result = self.invoke_command(console, chain_click, ["v2"])

            self.assert_success(result)
            assert "Etherscan v2 supports 3 chains" in result.output
            assert "Ethereum" in result.output
            assert "✓ Online" in result.output
            assert "✗ Offline" in result.output
