.PHONY: docs

docs:
	sphinx-autobuild docs/en docs/en/_build

cn_docs:
	sphinx-autobuild docs/cn docs/cn/_build

publish:
	rm -r dist
	python -m build
	twine upload dist/*

install:
	python setup.py install

uninstall:
	pip uninstall peth