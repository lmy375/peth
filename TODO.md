# TODO List for Peth Project

Based on the comprehensive code review, here's a prioritized list of improvements needed for the peth project.

## 🔴 Priority 1: Critical Security Fixes (Immediate)

### Security Vulnerabilities
- [ ] **Remove eval() and os.system() calls** in `console.py:382` and `console.py:376`
  - Replace with safe command execution using subprocess with whitelist
  - Implement proper input validation
- [ ] **Replace pickle serialization** in `peth/eth/evm/forkchain.py`
  - Use JSON or other safe serialization formats
  - Implement signature verification if pickle must be used
- [ ] **Remove hardcoded API keys** from `peth/data/chains.yaml`
  - Implement environment variable support
  - Create `.env.example` file with required variables
  - Update documentation for API key configuration

### Private Key Security
- [ ] **Improve private key handling** in `peth/eth/web3ex.py`
  - Implement encrypted key storage
  - Add support for hardware wallets
  - Never log or display private keys

## 🟡 Priority 2: Code Quality Improvements (Short-term)

### Code Refactoring
- [ ] **Split console.py** (2200+ lines) into multiple modules
  - Create `commands/` directory with categorized command modules
  - Implement command registry pattern
  - Keep console.py as a thin orchestration layer
- [ ] **Standardize error handling**
  - Replace broad `except Exception` with specific exceptions
  - Create custom exception classes
  - Implement consistent error messages and logging

### Input Validation
- [ ] **Add comprehensive input validation**
  - Validate addresses, transaction hashes, and other user inputs
  - Implement parameter type checking
  - Add bounds checking for numeric inputs

## 🟠 Priority 3: Testing and CI/CD (Medium-term)

### Testing Infrastructure
- [ ] **Set up pytest-cov** for test coverage reporting
  - Target: 80% code coverage
  - Add coverage badge to README
- [ ] **Add missing tests** for core modules:
  - `cli.py`, `console.py`
  - `core/analysis.py`, `core/config.py`
  - `util/` modules
- [ ] **Implement different test types**
  - Unit tests with mocking
  - Integration tests
  - End-to-end tests

### CI/CD Pipeline
- [ ] **Create comprehensive GitHub Actions workflow**
  - Run tests on every PR and push
  - Add linting (flake8, pylint)
  - Add type checking (mypy)
  - Security scanning (bandit)
  - Dependency vulnerability scanning
- [ ] **Add pre-commit hooks**
  - Code formatting (black, isort)
  - Linting
  - Test execution

## 🟢 Priority 4: Performance and Scalability (Long-term)

### Performance Optimization
- [ ] **Implement async/await support**
  - Use aiohttp for network requests
  - Add asyncio for concurrent operations
  - Create async versions of key methods
- [ ] **Optimize caching mechanism**
  - Implement LRU cache with size limits
  - Add TTL (time-to-live) for cached items
  - Use memory-efficient data structures
- [ ] **Improve memory management**
  - Fix file handle leaks (use context managers)
  - Implement streaming for large file processing
  - Add memory profiling

### Architecture Improvements
- [ ] **Create plugin system**
  - Define plugin interfaces
  - Support dynamic loading
  - Document plugin development
- [ ] **Implement batch operations**
  - Add batch API for multiple requests
  - Support bulk data processing
  - Implement pagination for large results

## 📚 Priority 5: Documentation and Tooling

### Documentation
- [ ] **Enhance developer documentation**
  - Architecture overview
  - Plugin development guide
  - API reference (auto-generated)
- [ ] **Improve contribution guidelines**
  - Code style guide
  - Commit message conventions
  - PR and issue templates

### Development Tools
- [ ] **Unify dependency management**
  - Choose between Poetry and pip/requirements.txt
  - Update installation instructions
- [ ] **Add code quality tools**
  - Configure black for formatting
  - Set up isort for import sorting
  - Add .editorconfig for consistency

## 📊 Tracking and Metrics

### Success Metrics
- Security vulnerabilities: 0
- Test coverage: >80%
- Code quality score: A (via CodeClimate or similar)
- Performance: <100ms response time for common operations
- Documentation coverage: 100% of public APIs

### Timeline Estimates
- Priority 1: 1-2 weeks
- Priority 2: 2-3 weeks
- Priority 3: 3-4 weeks
- Priority 4: 4-6 weeks
- Priority 5: Ongoing

---

**Note**: This TODO list should be reviewed and updated regularly. Consider converting these items into GitHub issues for better tracking and collaboration.