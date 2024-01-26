# Transaction Explainer

A tool decodes the EVM transaction and gives explanations according to pre-configured patterns.

# Usage

```
# Install peth if not exists
$ pip install git+https://github.com/lmy375/peth

# Start txexpl server.
$ python -m peth.tools.txexpl.server.server
```

Open http://localhost:8000/. Drag the button to your bookmarks bar.

Click the bookmark on a [Transaction Etherscan page](https://etherscan.io/tx/0x69120b25c790dbcbd5e50abb6ac8f402b905a26741f4f4f1a20745d1f534e9c8) to explain it.

If you'd like to use it while signing, add [this file](server/monkey.js) to your [tampermonkey](https://www.tampermonkey.net/) of the browser. If intercepts before you send transactions and sign Safe transactions.

# Explanations

You can add your own `Explanation`.

A sample case is like:
```
swapExactTokensForTokens: 'Sell {{amountIn:balance:path[0]}} {{path[0]}} to buy >= {{amountOutMin:balance:path[-1]}} {{path[-1]}}. Swap path: {{path}}'
```

It renders to things below for this [transaction](https://etherscan.io/tx/0xa52c02055248e1c740186e39d684230efea468129bc8125de9788205254cb54c)

> Sell 0.060000 * 1e18 [WETH](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) to buy >= 80411.639109 * 1e18 [MOLLY](https://etherscan.io/address/0x24289e2F9CDc03787E24997Df5438bA8045bC9B2). Swap path: [WETH](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) -> [MOLLY](https://etherscan.io/address/0x24289e2F9CDc03787E24997Df5438bA8045bC9B2)


The grammar:
```
explanation := KEY ":" expl_text
expl_text := ( ASCII | "{{" param "}}")+
param := func_param ( ":" HINT ( ":" HINT_ARGS )? )?
func_param := NAME | NUMBER ( "." NAME | NUMBER )*
```

- KEY: ABI function name or full signature or 4-bytes-selector
- ASCII: Any ASCII string with out `{{` and `}}` in it
- NAME: Solidity argument name or tuple member name
- NUMBER: the index in definition.
- HINT: Formatter for extracted values
- HINT_ARGS: Arguments for the hint.

Current hint supported:
- `balance:token` A token balance in decimals of token
- `path` DEX Swap path
- `names:[[key, value]]` If the extracted value matches the key, return the value.

See more examples [here](explanations.yaml).

# Sub Call

Sometimes, transaction metadata can be used as parameters to pass into solidity methods. (Consider when you are using a smart contract wallet)

[here](subcalls.yaml) tells how to use the parameters as a transaction. 

Here is the case for [ERC-4337 handleOps()](https://etherscan.io/tx/0x69120b25c790dbcbd5e50abb6ac8f402b905a26741f4f4f1a20745d1f534e9c8)
```
handleOps:
  count: ops.length
  to: ops[#].sender
  data: ops[#].callData
```

The `#` above means the decoder should fill an array index from `0` to `count`.

