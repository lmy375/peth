from peth import Peth
from peth.core.config import config
from peth.eth.utils import ZERO_ADDRESS


def test_all_tokens():
    for chain, tokens in config.tokens.items():

        token_infos = {}
        for token in tokens:
            token_infos[token["address"].lower()] = token

        p = Peth.get_or_create(chain)

        token_balances = p.get_token_balances(list(token_infos.keys()), [ZERO_ADDRESS])
        print(f"{chain} {len(token_balances)}")
