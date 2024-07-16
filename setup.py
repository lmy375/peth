from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

requires = open("requirements.txt").read().splitlines()
requires = list(filter(lambda x: not x.startswith("#"), requires))

setup(
    name="peth",
    description="An all-in-one Ethereum SDK and command-line tool written in Python.",
    url="https://github.com/lmy375/peth",
    author="Moon",
    version="1.0.8",
    packages=find_packages(exclude=["tests", "scripts"]),
    python_requires=">=3.8",
    install_requires=requires,
    license="AGPL-3.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "peth = peth.cli:main",
            "tx-expl-server = peth.tools.txexpl.server.server:main",
        ]
    },
    include_package_data=True,
)
