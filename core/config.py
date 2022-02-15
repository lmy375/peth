import os
import json

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CONFIG_PATH = os.path.join(BASE_PATH, 'config.json')

config = json.load(open(CONFIG_PATH))
