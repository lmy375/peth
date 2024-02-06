from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="peth",
    description="A python Ethereum utilities command-line tool.",
    url="https://github.com/lmy375/peth",
    author="Moon",
    version="0.1.6",
    packages=find_packages(exclude=['tests',"peth/4byte.json"]),
    package_data={'peth': ['*.json'] },
    python_requires=">=3.8",
    install_requires=[
        "crytic_compile==0.2.3",
        "eth_abi==2.2.0",
        "py_solc_x==1.1.1",
        "pycryptodome==3.16.0",
        "pysha3==1.0.2",
        "requests==2.28.1",
        "sha3==0.2.1",
        "web3==5.31.1",
        "eth_account==0.5.9"
    ],
    license="AGPL-3.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "peth = peth.__main__:main"
        ]
    }
)
