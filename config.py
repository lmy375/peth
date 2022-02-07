import os
import json

BASE_PATH = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_PATH, 'config.json')
DEFAULT_API_INTERVAL = 6

config = json.load(open(CONFIG_PATH))
