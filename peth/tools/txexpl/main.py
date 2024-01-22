from .txexpl import TxExplainer

txs = [
     "0xe012b2e0b4f79cbc4e20c634557b6e1826ec3ae3a49cb909d56dd87f0aa0d715", # Balancer swap
     "0xfc1bacf1d3be11536c5bd7f6032c6e546f0c9a1029cab41ee778c507c1174926", # USDT transfer
     "0xa52c02055248e1c740186e39d684230efea468129bc8125de9788205254cb54c", # Uniswap.swapExactTokensForTokens
]

txe = TxExplainer("eth")
# for txid in txs:
#     s = txe.explain_tx(txid)
#     print(s)
print(txe.value_map_to_md(txe.decode_tx(txs[0])))