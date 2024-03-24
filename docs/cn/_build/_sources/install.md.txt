
# Install 安装

## From pip 

1. Install with pip. 通过 pip 安装。
```
$ python -m venv test
$ source test/bin/activate

$ pip install peth
# or
$ pip install git+https://github.com/lmy375/peth
```

2. Run peth。运行 peth。
```
$ peth -h
```

## From source

1. Clone the repo. 克隆本仓库。

```
git clone https://github.com/lmy375/peth
```
2. (Optional) Edit `config.json` with new EVM network RPC endpoints and your Etherscan API keys. （可选的）编辑根目录下的 `config.json` 文件，添加自定义的 RPC 地址。添加 API Key 可以提高执行速度（否则限频时会自动等待）。

```json
{
    "chains": {
        "eth": [
            // RPC endpoint URL.
            "https://rpc.ankr.com/eth",  

            // Etherscan-style API URL.
            // Get better experience if you have an API key.
            // https://api.etherscan.io/api?apikey=<Your API Key>&
            // Do NOT forget the '?' or '&' in the URL.
            "https://api.etherscan.io/api?",
            
            // Etherscan address page URL.
            "https://etherscan.io/address/"
        ],

      //...
    }
}
```