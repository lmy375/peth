#!/bin/bash
# Script to run Peth tests by category

set -e

echo "Peth Test Runner"
echo "================"
echo

if [ "$1" = "no-deps" ] || [ "$1" = "ci" ]; then
    echo "Running tests without external dependencies (CI-safe)..."
    uv run pytest tests/test_commands/test_no_deps.py -v
elif [ "$1" = "with-deps" ] || [ "$1" = "external" ]; then
    echo "Running tests with external dependencies..."
    uv run pytest tests/test_commands/test_with_deps.py -v
elif [ "$1" = "original" ]; then
    echo "Running original test suite..."
    uv run pytest tests/test_commands/test_*.py -v \
        --ignore=tests/test_commands/test_no_deps.py \
        --ignore=tests/test_commands/test_with_deps.py
elif [ "$1" = "all" ]; then
    echo "Running all tests..."
    uv run pytest tests/test_commands/ -v
elif [ "$1" = "coverage" ]; then
    echo "Running tests with coverage report..."
    uv run pytest tests/test_commands/test_no_deps.py \
        --cov=peth --cov-report=html --cov-report=term-missing
    echo "Coverage report generated in htmlcov/"
else
    echo "Usage: $0 [no-deps|with-deps|original|all|coverage]"
    echo
    echo "Options:"
    echo "  no-deps    - Run tests without external dependencies (CI-safe)"
    echo "  with-deps  - Run tests requiring external services"
    echo "  original   - Run the original test suite"
    echo "  all        - Run all tests"
    echo "  coverage   - Run no-deps tests with coverage report"
    exit 1
fi