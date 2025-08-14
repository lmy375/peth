.PHONY: docs

docs:
	uv run sphinx-autobuild docs/en docs/en/_build

cn_docs:
	uv run sphinx-autobuild docs/cn docs/cn/_build

release:
	rm -rf dist
	uv build

publish:
	uv publish

test:
	uv run pytest

test-no-deps:
	uv run pytest tests/test_commands/test_no_deps.py -v

test-with-deps:
	uv run pytest tests/test_commands/test_with_deps.py -v

test-original:
	uv run pytest tests/test_commands/test_*.py -v \
		--ignore=tests/test_commands/test_no_deps.py \
		--ignore=tests/test_commands/test_with_deps.py

test-coverage:
	uv run pytest tests/test_commands/test_no_deps.py \
		--cov=peth --cov-report=html --cov-report=term-missing

install:
	uv pip install -e .

uninstall:
	uv pip uninstall peth
