.PHONY: docs

docs:
	sphinx-autobuild docs/en docs/en/_build

cn_docs:
	sphinx-autobuild docs/cn docs/cn/_build

release:
	rm -rf dist
	python -m build

publish:
	twine upload dist/*

test:
	pytest

install:
	python setup.py install

uninstall:
	pip uninstall peth