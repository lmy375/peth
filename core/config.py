import os
import json

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CHAIN_CONFIG_PATH = os.path.join(BASE_PATH, 'config.json')
CACHE_PATH = os.path.join(BASE_PATH, '.contract_info_cache')

DEFAULT_API_INTERVAL = 6

chain_config = json.load(open(CHAIN_CONFIG_PATH))

DIFF_MIN_SIMILARITY = 0.1

def print_config():
    print("DIFF_MIN_SIMILARITY", DIFF_MIN_SIMILARITY)
    print("DEFAULT_API_INTERVAL", DEFAULT_API_INTERVAL)