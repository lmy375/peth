import os
import json

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CHAIN_CONFIG_PATH = os.path.join(BASE_PATH, 'config.json')
CACHE_PATH = os.path.join(BASE_PATH, '.contract_info_cache')

DEFAULT_API_INTERVAL = 6

user_config = json.load(open(CHAIN_CONFIG_PATH))
chain_config = user_config["chains"]
contracts_config = user_config["contracts"]

DIFF_MIN_SIMILARITY = 0.5

def print_config():
    print("DIFF_MIN_SIMILARITY", DIFF_MIN_SIMILARITY)
    print("DEFAULT_API_INTERVAL", DEFAULT_API_INTERVAL)