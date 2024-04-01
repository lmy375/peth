from peth.__main__ import main
from peth.core.config import config

config.cfg.set("path", "root", "peth-data")

# Start.
main()
