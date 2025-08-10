# Etherscan V2 API Support

Peth now supports both Etherscan v1 and v2 APIs. The v2 API allows you to access 60+ EVM-compatible chains with a single Etherscan API key.

## Features

### 1. Environment Variable Based API Keys
API keys are now configured through environment variables specified in `chains.yaml`. Each chain has an `api_key_env` field that points to the environment variable containing the API key.

### 2. Etherscan V2 API Support
- Use a single Etherscan API key to access multiple chains
- Supported chains include Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, and many more
- V2 API endpoint: `https://api.etherscan.io/v2/api`

### 3. Automatic v1/v2 Detection
The system automatically detects whether to use v1 or v2 API based on:
- Chain configuration
- Explicit `use_v2` parameter
- API URL patterns

## Configuration

### Setting Up API Keys

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Add your API keys:
```env
# For v2 API - single key for all Etherscan-supported chains
ETHERSCAN_API_KEY=your_etherscan_api_key

# For v1 API or chain-specific explorers
BSCSCAN_API_KEY=your_bscscan_api_key
POLYGONSCAN_API_KEY=your_polygonscan_api_key
# ... other keys as needed
```

## Usage

### Console Commands

#### Using v1 API (default)
```bash
# Switch to a chain using v1 API
chain eth
chain bsc
```

#### Using v2 API
```bash
# Switch to a chain using v2 API
chain eth v2
chain bsc v2

# Use v2 API with any supported chain ID
chain v2 1      # Ethereum
chain v2 56     # BSC
chain v2 137    # Polygon
chain v2 42161  # Arbitrum
```

### Python API

#### Using v1 API
```python
from peth import Peth

# Create instance with v1 API (default)
peth = Peth.get_or_create('eth')
peth = Peth.get_or_create('eth', use_v2=False)
```

#### Using v2 API
```python
from peth import Peth
from peth.eth.scan import ScanAPI

# Create instance with v2 API
peth = Peth.get_or_create('eth', use_v2=True)

# Create v2 API instance for any chain ID
scan_v2 = ScanAPI.get_or_create_v2(1)      # Ethereum
scan_v2 = ScanAPI.get_or_create_v2(56)     # BSC
scan_v2 = ScanAPI.get_or_create_v2(137)    # Polygon
```

## Supported Chains

The v2 API supports 60+ chains. Some popular ones include:

| Chain | Chain ID | V2 Support |
|-------|----------|------------|
| Ethereum | 1 | ✓ |
| BSC | 56 | ✓ |
| Polygon | 137 | ✓ |
| Arbitrum | 42161 | ✓ |
| Optimism | 10 | ✓ |
| Base | 8453 | ✓ |
| Avalanche | 43114 | ✓ |
| Fantom | 250 | ✓ |
| Gnosis | 100 | ✓ |

## Migration Guide

### From v1 to v2

1. Ensure you have an Etherscan API key
2. Set `ETHERSCAN_API_KEY` in your `.env` file
3. Use `use_v2=True` when creating Peth instances or add `v2` to chain commands

### Backward Compatibility

- All existing code continues to work with v1 API by default
- Chain-specific API keys (BSCSCAN_API_KEY, etc.) are still supported
- V1 endpoints remain unchanged

## Important Notes

1. **V2 API Deadline**: Etherscan v1 API will be disabled after May 31, 2025
2. **Rate Limits**: V2 API uses the same rate limits as v1
3. **Not All Chains**: Some chains may not be supported by v2 API yet
4. **Caching**: Both v1 and v2 responses are cached to minimize API calls