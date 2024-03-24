from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

requires = open("requirements.txt").read().splitlines()
requires = filter(lambda x: not x.startswith("#"), requires)

setup(
    name="peth",
    description="A python Ethereum utilities command-line tool.",
    url="https://github.com/lmy375/peth",
    author="Moon",
    version="0.1.6",
    packages=find_packages(exclude=["tests", "peth/4byte.json"]),
    package_data={"peth": ["*.json"]},
    python_requires=">=3.8",
    install_requires=requires,
    license="AGPL-3.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points={"console_scripts": ["peth = peth.__main__:main"]},
)
