import json
import os
import sys
from configparser import ConfigParser

import yaml

PETH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PETH_ROOT, "data")
CONFIG_FILE_NAME = "config.ini"


class PethConfig(object):

    def __init__(self, config_file=CONFIG_FILE_NAME) -> None:
        self.load(config_file)
        self.load_chains(self.chains_path)
        self.load_contracts(self.contracts_path)
        self.load_tokens(self.tokens_path)

    def load(self, cfg_file):
        self.config_path = self._find_file(cfg_file, ".", DATA_DIR)
        self.cfg = ConfigParser()
        self.cfg.read(self.config_path, "utf-8")

    def load_chains(self, filename):
        self.chains = self.load_yaml(filename)

    def load_contracts(self, filename):
        self.contracts = self.load_yaml(filename)

    def load_tokens(self, dir):
        assert os.path.isdir(dir), f"dir {dir} not found."

        self.tokens = {}
        for name in os.listdir(dir):
            chain = name.split(".")[0]
            path = os.path.join(dir, name)
            with open(path, encoding="utf-8") as f:
                tokens = json.load(f)
            self.tokens[chain] = tokens

    def load_yaml(self, chain_file):
        with open(chain_file) as f:
            return yaml.safe_load(f)

    @property
    def root(self):
        return os.path.realpath(
            os.path.expanduser(os.path.expandvars(self.cfg.get("path", "root")))
        )

    @property
    def chains_path(self):
        return self._find_file(self.cfg.get("root", "chains"), self.root, DATA_DIR)

    @property
    def tokens_path(self):
        return self._find_file(self.cfg.get("root", "tokens"), self.root, DATA_DIR)

    @property
    def contracts_path(self):
        return self._find_file(self.cfg.get("root", "contracts"), self.root, DATA_DIR)

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
