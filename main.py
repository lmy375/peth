import os

from peth.core import config
from peth.__main__ import main

# Set output to current folder.
config.OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'output')

# Start.
main()