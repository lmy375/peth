# 贡献代码

1. 在 Github 中 Fork https://github.com/lmy375/peth.

2. 克隆仓库并安装相应依赖。

```sh
$ python -m venv pethenv
$ source pethenv/bin/activate

$ git clone https://github.com/<your-peth>/peth

$ cd peth

$ pip install -r requirements.txt
$ pip install -r requirements-dev.txt

$ pre-commit install --install-hooks
```

3. 修改代码，添加单元测试。保证单元测试完整通过

```sh
$ pytest
================================== test session starts ==================================
...                                                                 

tests/test_abi.py .....                                                           [ 45%]
tests/test_bytecode.py .                                                          [ 54%]
tests/test_sigs.py ....                                                           [ 90%]
tests/test_source.py .                                                            [100%]

...
============================ 11 passed, 2 warnings in 10.05s ============================
```

4. 更新对应的文档

5. 在 Github 上提交 Pull request.