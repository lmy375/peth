import os

from peth.core import config
from peth.__main__ import main

# Set output to current folder.
config.OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'output')
config.CACHE_PATH = os.path.join(config.OUTPUT_PATH, 'contract_info_cache')
config.DIFF_PATH = os.path.join(config.OUTPUT_PATH, 'diff')
config.REPORT_PATH = os.path.join(config.OUTPUT_PATH, 'report')
config.SOURCE_PATH = os.path.join(config.OUTPUT_PATH, 'sources')


# Start.
main()