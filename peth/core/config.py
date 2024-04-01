import os
import sys
from configparser import ConfigParser

import yaml

PETH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_DIR = os.path.join(PETH_ROOT, "config")
CONFIG_FILE_NAME = "config.ini"


class PethConfig(object):

    def __init__(self, config_file=CONFIG_FILE_NAME) -> None:
        self.load(config_file)

    def load(self, cfg_file):
        self.config_path = self._find_file(cfg_file, ".", CONFIG_DIR)
        self.cfg = ConfigParser()
        self.cfg.read(self.config_path, "utf-8")

        self.chains = self.load_yaml(self.chains_path)
        self.tokens = self.load_yaml(self.tokens_path)
        self.contracts = self.load_yaml(self.contracts_path)

    def load_yaml(self, chain_file):
        return yaml.safe_load(open(chain_file))

    @property
    def root(self):
        return os.path.realpath(
            os.path.expanduser(os.path.expandvars(self.cfg.get("path", "root")))
        )

    @property
    def chains_path(self):
        return self._find_file(self.cfg.get("root", "chains"), self.root, CONFIG_DIR)

    @property
    def tokens_path(self):
        return self._find_file(self.cfg.get("root", "tokens"), self.root, CONFIG_DIR)

    @property
    def contracts_path(self):
        return self._find_file(self.cfg.get("root", "contracts"), self.root, CONFIG_DIR)

    @property
    def output_path(self):
        return os.path.join(self.root, self.cfg.get("root", "output"))

    @property
    def sig_db_path(self):
        return os.path.join(self.root, self.cfg.get("root", "sig_db"))

    @property
    def cache_path(self):
        return os.path.join(self.root, self.cfg.get("root", "cache"))

    @property
    def diff_path(self):
        return os.path.join(self.output_path, self.cfg.get("output", "diff"))

    @property
    def report_path(self):
        return os.path.join(self.output_path, self.cfg.get("output", "report"))

    @property
    def sources_path(self):
        return os.path.join(self.output_path, self.cfg.get("output", "sources"))

    @property
    def evm_cache_path(self):
        return os.path.join(self.cache_path, self.cfg.get("cache", "evm"))

    @property
    def contracts_cache_path(self):
        return os.path.join(self.cache_path, self.cfg.get("cache", "contracts"))

    @property
    def scan_api_interval(self):
        return self.cfg.getint("misc", "scan_api_interval")

    @property
    def sig_db_url(self):
        return self.cfg.get("misc", "sig_db_url")

    @property
    def diff_min_similarity(self):
        return self.cfg.getfloat("misc", "diff_min_similarity")

    @property
    def enable_slither(self):
        return self.cfg.getboolean("misc", "enable_slither")

    def _find_file(self, file, *dirs):
        if os.path.exists(file):
            return file

        for dir in dirs:
            path = os.path.join(dir, file)
            if os.path.exists(path):
                return path

        raise FileNotFoundError(f"{file} not found")

    def print_config(self):
        for name, value in self.__class__.__dict__.items():
            if isinstance(value, property):
                print(name, "=", getattr(self, name))

    def print_ini(self):
        self.cfg.write(sys.stdout)


config = PethConfig()
