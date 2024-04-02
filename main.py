from peth.cli import main
from peth.core.config import config

if __name__ == "__main__":
    config.cfg.set("path", "root", "peth-data")
    main()
