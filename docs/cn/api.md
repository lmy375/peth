# API

## contract

导入 peth 并实例化。
```
In [1]: from peth import Peth

In [2]: p = Peth.get_or_create('ftm')
```

绑定 signer
```
In [3]: p.signer

In [4]: p.bind_signer('<Your private key>')

In [5]: p.signer
Out[5]: <eth_account.signers.local.LocalAccount at 0x10491c550>
```

实例化合约，注意 peth 会自动根据合约地址获取 ABI。这里使用 [WFTM 合约](https://ftmscan.com/address/0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83#code)
```
In [6]: wftm = p.contract('0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83')
```

调用 name, balanceOf 方法
```
In [7]: wftm.name
Out[7]: Function(function name() view returns (string ))

In [8]: wftm.name()
Out[8]: 'Wrapped Fantom'

In [9]: wftm.balanceOf(p.signer.address)
Out[9]: 0
```

调用 deposit 方法
```
In [10]: wftm.deposit
Out[10]: Function(function deposit() payable returns (uint256 ))

In [11]: wftm.deposit(value=1)
Out[11]: 
AttributeDict({'blockHash': HexBytes('0x00...'),
    ...
 'status': 1,
 'transactionHash': HexBytes('0x00...'),
 'transactionIndex': 2,
 'type': '0x0'})

In [12]: wftm.balanceOf(p.signer.address)
Out[12]: 1
```

调用 transfer 方法
```
In [13]: wftm.transfer(p.signer.address, 1)
Out[13]: 
AttributeDict({
    ....
 'status': 1,
    ....
 })
```

## call

无 ABI 信息时调用合约
```
In [1]: from peth import Peth

In [2]: p = Peth.get_or_create('ftm')

In [3]: p.call('0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83', 'name()')
Out[3]: '0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e577261707065642046616e746f6d000000000000000000000000000000000000'

In [4]: p.call('0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83', 'name()->(string)')
Out[4]: 'Wrapped Fantom'

In [5]: p.call('0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83', 'balanceOf(address)->(uint256)', ['0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83'])
Out[5]: 5913518704387658333840
```

## ABI

```
In [1]: from peth import Peth

In [2]: p = Peth.get_or_create('ftm')

In [3]: abi_raw = p.scan.get_abi('0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83')

In [4]: abi_raw
Out[4]: 
[{'inputs': [],
  'payable': False,
  'stateMutability': 'nonpayable',
  'type': 'constructor'},
 {'anonymous': False,
  'inputs': [{'indexed': True,
    'internalType': 'address',
    ...
    
In [5]: from peth.eth.abi import ABI

In [6]: abi = ABI(abi_raw)

In [7]: abi
Out[7]: <peth.eth.abi.abi.ABI at 0x10420cf40>

In [8]: abi.functions
Out[8]: 
{'ERR_INVALID_ZERO_VALUE': function ERR_INVALID_ZERO_VALUE() view returns (uint256 ),
 'ERR_NO_ERROR': function ERR_NO_ERROR() view returns (uint256 ),
 'addPauser': function addPauser(address account) nonpayable returns (),
 'allowance': function allowance(address owner, address spender) view returns (uint256 ),
 'approve': function approve(address spender, uint256 value) nonpayable returns (bool ),
 'balanceOf': function balanceOf(address account) view returns (uint256 ),
  ...

In [9]: abi.transfer
Out[9]: function transfer(address to, uint256 value) nonpayable returns (bool )

In [10]: abi['0xa9059cbb']
Out[10]: function transfer(address to, uint256 value) nonpayable returns (bool )

In [11]: abi['transfer(address,uint256)']
Out[11]: function transfer(address to, uint256 value) nonpayable returns (bool )

In [12]: transfer = abi.transfer

In [13]: transfer.signature
Out[13]: 'transfer(address,uint256)'

In [14]: transfer.func_type
Out[14]: 'nonpayable'

In [15]: transfer.selector
Out[15]: HexBytes('0xa9059cbb')

In [16]: transfer.simple
Out[16]: 'transfer(address,uint256)->(bool) nonpayable'

In [17]: transfer.full
Out[17]: 'function transfer(address to, uint256 value) nonpayable returns (bool )'

In [18]: calldata = abi.transfer.encode_input(['0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 10])

In [19]: calldata
Out[19]: HexBytes('0xa9059cbb000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000000000000000000000000000000000000000000000000000000000a')

In [20]: values = abi.transfer.decode_input(calldata)

In [21]: values
Out[21]: ('0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 10)

In [22]: transfer.map_values(values)
Out[22]: [('to', '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'), ('value', 10)]

In [23]: transfer.extract_value('to', values)
Out[23]: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'

In [24]: transfer.explain_calldata('to: {{to}} value: {{value}}', calldata)
Out[24]: 'to: 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee value: 10'
```

## Etherscan

```
In [1]: WFTM = '0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83'

In [2]: scan = p.scan

In [3]: scan.get_contract_info(WFTM).keys()
Out[3]: dict_keys(['SourceCode', 'ABI', 'ContractName', 'CompilerVersion', 'OptimizationUsed', 'Runs', 'ConstructorArguments', 'EVMVersion', 'Library', 'LicenseType', 'Proxy', 'Implementation', 'SwarmSource'])

In [4]: scan.get_contract_name(WFTM)
Out[4]: 'WrappedFtm'

In [5]: scan.get_source(WFTM)[:100]
Out[5]: 'pragma solidity ^0.5.0;\r\n\r\ncontract Context {\r\n    // Empty internal constructor, to prevent people '

In [6]: name, ver, std_input = scan.get_standard_json_input(WFTM)

In [7]: name
Out[7]: 'WrappedFtm'

In [8]: ver
Out[8]: '0.5.17'

In [9]: std_input.keys()
Out[9]: dict_keys(['language', 'sources', 'settings'])

In [10]: import solcx

In [11]: out = solcx.compile_standard(std_input, solc_version=ver)

In [12]: out.keys()
Out[12]: dict_keys(['contracts', 'sources'])

In [13]: out["contracts"].keys()
Out[13]: dict_keys(['WrappedFtm.sol'])

In [14]: out["contracts"]['WrappedFtm.sol'].keys()
Out[14]: dict_keys(['Context', 'ERC20', 'ERC20Detailed', 'ERC20Pausable', 'IERC20', 'Pausable', 'PauserRole', 'Roles', 'SafeMath', 'WrappedFtm'])


In [15]: out["contracts"]['WrappedFtm.sol']["WrappedFtm"].keys()
Out[15]: dict_keys(['abi', 'devdoc', 'evm', 'metadata', 'userdoc'])

In [16]: out["contracts"]['WrappedFtm.sol']["WrappedFtm"]["evm"].keys()
Out[16]: dict_keys(['bytecode', 'deployedBytecode'])

In [17]: out["contracts"]['WrappedFtm.sol']["WrappedFtm"]["evm"]["bytecode"].keys()
Out[17]: dict_keys(['linkReferences', 'object', 'opcodes', 'sourceMap'])

In [18]: out["contracts"]['WrappedFtm.sol']["WrappedFtm"]["evm"]["bytecode"]["object"]
Out[18]: '60806040523480156200001157600080fd5b50604080518082018252600e81526d577261707065642046616e746f6d60901b6020808301918252835180850190945260048452635746544d60e01b90840152815191929160129162000068916003919062000210565b5081516200007e90600490602085019062000210565b506005805460ff191660ff9290921691909117905550620000b39050620000a4620000c3565b6001600160e01b ...
```