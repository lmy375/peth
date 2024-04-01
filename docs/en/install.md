
# Installation

## Preparation

It is recommended to create a Python virtual environment before installation.
```sh
$ python -m venv pethenv
$ source pethenv/bin/activate
```

## From pypi

```sh
# install
$ pip install peth

# run
$ peth -h
```

## From github

The recommended way to get the latest release.

```sh
# install
$ pip install git+https://github.com/lmy375/peth

# run
$ peth -h
```

## From source

```sh
# download
$ git clone https://github.com/lmy375/peth
$ pip install -r requirements.txt

# run
$ cd peth
$ python main.py -h
```

## Customized RPC and API Key

Edit the `chains.yaml` file in the peth directory. If installed via pip, the file is located in the corresponding package in `site-packages`.

Add custom RPC addresses to support new EVM chains, and you are welcome to submit a Github Pull Request.

Adding an API Key can speed up execution, otherwise it will automatically wait when encountering API rate limits.

```yaml
eth:
# Node RPC address
- "https://rpc.ankr.com/eth",

# Etherscan API URL, be careful not to miss the trailing ?
# Only supports Etherscan compatible blockchain explorers
# If you want to add an API Key, use this format
# https://api.etherscan.io/api?apikey=<Your API Key>&
- "https://api.etherscan.io/api?",


# URL for opening a specific address
- "https://etherscan.io/address/"

bsc:
# You can continue to add new chains
```