import os
import json

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

if os.path.exists('config.json'): 
    # If we found config file, set current dir as workspace.
    CHAIN_CONFIG_PATH = 'config.json'
    SIG_DB_PATH = '4byte.json'
    OUTPUT_PATH = 'output'
else:
    # Default path.
    CHAIN_CONFIG_PATH = os.path.join(BASE_PATH, 'config.json')
    SIG_DB_PATH = os.path.join(BASE_PATH, '4byte.json')
    OUTPUT_PATH = os.path.expanduser('~/.peth')

SIG_DB_URL = "https://raw.githubusercontent.com/ethereum/go-ethereum/master/signer/fourbyte/4byte.json"

CACHE_PATH = os.path.join(OUTPUT_PATH, 'contract_info_cache')
DIFF_PATH = os.path.join(OUTPUT_PATH, 'diff')
DIFF_TMP_FILE = os.path.join(OUTPUT_PATH, 'diff', 'tmp.sol')
REPORT_PATH = os.path.join(OUTPUT_PATH, 'report')
SOURCE_PATH = os.path.join(OUTPUT_PATH, 'sources')

DEFAULT_API_INTERVAL = 6

user_config = json.load(open(CHAIN_CONFIG_PATH))
chain_config = user_config["chains"]
contracts_config = user_config["contracts"]

DIFF_MIN_SIMILARITY = 0.5

ENABLE_SLITHER = False

def print_config():
    for key, value in globals().items():
        if key.isupper():
            print("%s = %s" % (key, repr(value)))