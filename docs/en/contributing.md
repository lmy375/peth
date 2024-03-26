# Contributing

1. Fork https://github.com/lmy375/peth on Github.

2. Clone the repository and install the corresponding dependencies.

```sh
$ python -m venv pethenv
$ source pethenv/bin/activate

$ git clone https://github.com/<your-peth>/peth

$ cd peth

$ pip install -r requirements.txt
$ pip install -r requirements-dev.txt

$ pre-commit install --install-hooks
```

3. Modify the code or add new code, add unit tests. Ensure that all unit tests pass.

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

4. Update the corresponding documentation.

5. Submit a Pull request on Github.