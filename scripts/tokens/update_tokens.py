import json
import os

from peth import Peth

PETH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR = os.path.join(PETH_ROOT, "peth", "data", "tokens")


def main():
    assert os.path.isdir(DATA_DIR), f"{DATA_DIR} not valid"
    for name in os.listdir(DATA_DIR):
        print(f"------- {name} start -------")
        chain = name.split(".")[0]
        path = os.path.join(DATA_DIR, name)
        tokens = json.load(open(path, encoding="utf-8"))
        p = Peth.get_or_create(chain)

        for token in tokens:
            dec = p.call(token["address"], "decimals()->(uint256)")
            token["decimals"] = dec

            print(token["name"], token["address"], dec)

        json.dump(tokens, open(path, "w", encoding="utf-8"))
        print(f"------- {name} end -------")

    # TODO: Add ETH / WETH tokens.
    # TODO: Update price.


if __name__ == "__main__":
    main()
