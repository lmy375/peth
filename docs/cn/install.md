
# 安装

## 安装前的准备

建议创建 python 虚拟环境使用。
```sh
$ python -m venv pethenv
$ source pethenv/bin/activate
```

## 从 pypi 安装

```sh
# install
$ pip install peth

# run
$ peth -h
```

## 从 github 安装

> *注：建议的安装方式，可以获得最新特性*

```sh
# install
$ pip install git+https://github.com/lmy375/peth

# run
$ peth -h
```

## 克隆源码直接运行

```sh
# download
$ git clone https://github.com/lmy375/peth
$ pip install -r requirements.txt

# run
$ cd peth
$ python main.py -h
```

## 配置 RPC 及 API Key

编辑 peth 目录下的 `config.json` 文件。如果是通过 pip 形式安装，则文件位于 `site-packages` 中对应的包中。

添加自定义的 RPC 地址，以支持新的 EVM 链，，也欢迎提交 Github Pull Request。

添加 API Key 可以提高执行速度，否则遇到 API 限频时会自动等待。

```js
{
    "chains": {
        "eth": [
            // 节点 RPC 地址
            "https://rpc.ankr.com/eth",  

            // Etherscan API URL，注意不要少了末尾的 ?
            // 仅支持 Etherscan 系列的区块链浏览器
            "https://api.etherscan.io/api?",
            
            // 如果要添加 API Key 则使这样的格式
            // https://api.etherscan.io/api?apikey=<Your API Key>&

            // 用于打开特定地址的 URL
            "https://etherscan.io/address/"
        ],

       // 可继续添加新的链
    }
}
```