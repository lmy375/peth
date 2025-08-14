# Peth Test Commands

This directory contains tests for all Peth console commands. The tests are organized into two categories based on their dependencies.

## Test Structure

### 1. Tests Without External Dependencies (`test_no_deps.py`)

These tests verify pure logic and can run in any environment without external services:

- **Pure utility functions**: keccak256 hashing, integer conversions, time formatting
- **Console state management**: debug toggle, sender/signer validation
- **Data filtering/search**: address and token search logic
- **ABI encoding logic**: selector calculation, formatting

These tests run automatically in GitHub Actions on every commit.

### 2. Tests With External Dependencies (`test_with_deps.py`)

These tests require external services and are heavily mocked:

- **RPC/Web3 calls**: eth_call, gas estimation, storage reading, transaction sending
- **External APIs**: Chainlink oracles, Uniswap reserves, CoinGecko prices, Etherscan
- **File system operations**: contract downloads, verification, Solidity compilation
- **Transaction analysis**: fetching, tracing, graph generation

These tests should be run manually or in environments with proper setup.

## Running Tests

### Run all tests
```bash
make test
```

### Run only no-dependency tests (CI-safe)
```bash
pytest tests/test_commands/test_no_deps.py -v
```

### Run tests with external dependencies
```bash
pytest tests/test_commands/test_with_deps.py -v
```

### Run original test suite
```bash
pytest tests/test_commands/test_*.py -v --ignore=tests/test_commands/test_no_deps.py --ignore=tests/test_commands/test_with_deps.py
```

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/test.yml`) automatically runs:
- No-dependency tests on Python 3.10, 3.11, and 3.12
- Code linting with ruff and black
- Test coverage reporting

## Test Philosophy

The test separation follows these principles:

1. **No over-mocking**: Tests that only verify mock calls without testing actual logic are moved to the external dependency category
2. **Pure logic focus**: No-dependency tests focus on data transformations, calculations, and business logic
3. **CI reliability**: No-dependency tests can run reliably in any CI environment without setup
4. **Manual verification**: External dependency tests serve as integration checkpoints for manual testing

## Adding New Tests

When adding new tests:

1. If the test verifies pure logic without external calls → add to `test_no_deps.py`
2. If the test requires RPC, network, or file system → add to `test_with_deps.py`
3. If mocking makes the test meaningless → consider it an integration test for `test_with_deps.py`