"""Base test class and utilities for command tests."""

from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from web3 import Web3

from peth.console import PethConsole


class MockPeth(Mock):
    """Mock Peth instance for testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain = "eth"
        self.rpc_url = "http://localhost:8545"
        self.api_url = "https://api.etherscan.io/api"
        self.address_url = "https://etherscan.io/address/"
        self.sender = "0x0000000000000000000000000000000000000000"
        self.signer = None

        # Mock web3
        self.web3 = Mock(spec=Web3)
        self.web3.eth = Mock()
        self.web3.to_checksum_address = Web3.to_checksum_address
        self.web3.is_address = Web3.is_address
        self.web3.from_wei = Web3.from_wei
        self.web3.to_wei = Web3.to_wei
        self.web3.keccak = Web3.keccak

        # Mock scan
        self.scan = Mock()
        self.scan.get_contract_name = Mock(return_value="MockContract")
        self.scan.get_address_name = Mock(return_value="MockContract")
        self.scan.get_contract_info = Mock(return_value=None)


class MockConsole(PethConsole):
    """Mock console for testing commands."""

    def __init__(self):
        self.peth = MockPeth()
        self._debug = False

        # Bind commands
        from peth.core.registry import command_registry

        command_registry.bind_to_console(self)

    @property
    def web3(self):
        return self.peth.web3

    @property
    def eth(self):
        return self.peth.web3.eth

    @property
    def scan(self):
        return self.peth.scan


class CommandTestBase:
    """Base class for command tests."""

    @pytest.fixture
    def runner(self):
        """Create a Click test runner."""
        return CliRunner()

    @pytest.fixture
    def console(self):
        """Create a mock console instance."""
        return MockConsole()

    @pytest.fixture
    def mock_web3(self, console):
        """Get the mock web3 instance."""
        return console.web3

    @pytest.fixture
    def mock_peth(self, console):
        """Get the mock peth instance."""
        return console.peth

    def invoke_command(self, console, command_func, args=None, **kwargs):
        """Helper to invoke a Click command with the console context."""
        runner = CliRunner()
        args = args or []

        # Get the actual Click command from the wrapped function
        if hasattr(command_func, "_click_command"):
            click_command = command_func._click_command
        else:
            # For direct Click commands
            click_command = command_func

        # Create a context with the console as obj
        with runner.isolated_filesystem():
            result = runner.invoke(
                click_command, args, obj=console, catch_exceptions=False, **kwargs
            )
        return result

    def assert_success(self, result):
        """Assert command executed successfully."""
        assert (
            result.exit_code == 0
        ), f"Command failed: {result.output}\n{result.exception}"

    def assert_error(self, result, error_text=None):
        """Assert command failed with optional error message check."""
        assert result.exit_code != 0
        if error_text:
            assert error_text in result.output


# Common test data
TEST_ADDRESS = "0x1234567890123456789012345678901234567890"
TEST_ADDRESS2 = "0xabcdef0123456789abcdef0123456789abcdef01"
TEST_TX_HASH = "0x" + "a" * 64
TEST_BYTECODE = "0x608060405260043610603f5763ffffffff7c01"
TEST_CALLDATA = "0xa9059cbb000000000000000000000000abcdef0123456789abcdef0123456789abcdef010000000000000000000000000000000000000000000000000000000000000064"
TEST_SELECTOR = "0xa9059cbb"
TEST_SIGNATURE = "transfer(address,uint256)"
