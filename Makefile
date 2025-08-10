.PHONY: docs

docs:
	sphinx-autobuild docs/en docs/en/_build

cn_docs:
	sphinx-autobuild docs/cn docs/cn/_build

release:
	rm -rf dist
	uv build

publish:
	uv publish

test:
	uv run pytest

install:
	uv pip install -e .

uninstall:
	uv pip uninstall peth