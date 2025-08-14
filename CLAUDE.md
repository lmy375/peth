# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Peth is an all-in-one Ethereum SDK and command-line tool written in Python. It's designed for developers, smart contract auditors, web3 security researchers, and anyone working with EVM-compatible chains.

## Development Commands

### Testing
```bash
make test  # Run pytest test suite
```

### Documentation
```bash
make docs      # Build English documentation with Sphinx
make cn_docs   # Build Chinese documentation
```

### Build and Release
```bash
make release  # Build distribution packages with uv
make publish  # Publish to PyPI
make install  # Install the package locally
make uninstall  # Uninstall the package
```

### Development Setup
```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies using uv
uv sync

# Run from source
uv run python main.py
```

## Architecture Overview

### Core Structure
- **peth/** - Main package directory
  - **cli.py** - Command-line interface entry point
  - **console.py** - Interactive console with 50+ commands
  - **core/** - Core functionality
    - `peth.py` - Main Peth class extending Web3Ex
    - `analysis.py` - Account and project analysis
    - `tracer/` - EVM transaction tracing and debugging
  - **eth/** - Ethereum-specific functionality
    - `abi/` - ABI encoding/decoding utilities
    - `bytecode.py` - Bytecode analysis and disassembly
    - `contract.py` - Contract interaction wrapper
    - `scan.py` - Etherscan-compatible API integration
    - `web3ex.py` - Extended Web3 functionality
  - **data/** - Configuration files
    - `chains.yaml` - Multi-chain configuration
    - `config.ini` - Main configuration
    - `contracts.yaml` - Known contract addresses
    - `tokens.yaml` - Token information

### Key Design Patterns
1. **Multi-chain Support**: Chain configurations are stored in `peth/data/chains.yaml`. The system supports Ethereum, BSC, Polygon, Arbitrum, and other EVM chains.

2. **Caching System**: Contract data and ABIs are cached in `peth-data/cache/` directory to minimize API calls.

3. **Modular Commands**: Console commands are implemented as methods in the Console class, making it easy to add new functionality.

4. **Web3 Extension**: The Web3Ex class extends web3.py with additional functionality like automatic ABI fetching and contract verification.

## Usage Modes

1. **Command-line**: `peth -h`
2. **Interactive Console**: `peth` (launches interactive shell)
3. **SDK**: Import as Python library
   ```python
   from peth import Peth
   p = Peth.get_or_create('eth')
   ```

## Testing Guidelines

- Tests are located in the `tests/` directory
- Run tests with `make test` or `pytest`
- New features should include corresponding tests

## Dependencies

- Python 3.10+
- web3.py >=6.20.0
- uv for dependency management (Important: Do NOT use raw pip, use `uv pip` instead)
- py-solc-x for Solidity compilation