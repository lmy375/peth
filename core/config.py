import os
import json

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CHAIN_CONFIG_PATH = os.path.join(BASE_PATH, 'config.json')

OUTPUT_PATH = 'output' # Current work dir.
CACHE_PATH = os.path.join(OUTPUT_PATH, 'contract_info_cache')
DIFF_PATH = os.path.join(OUTPUT_PATH, 'diff')
REPORT_PATH = os.path.join(OUTPUT_PATH, 'report')
SOURCE_PATH = os.path.join(OUTPUT_PATH, 'sources')

DEFAULT_API_INTERVAL = 6

user_config = json.load(open(CHAIN_CONFIG_PATH))
chain_config = user_config["chains"]
contracts_config = user_config["contracts"]

DIFF_MIN_SIMILARITY = 0.5

def print_config():
    print("DIFF_MIN_SIMILARITY", DIFF_MIN_SIMILARITY)
    print("DEFAULT_API_INTERVAL", DEFAULT_API_INTERVAL)