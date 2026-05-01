"""
Fetch and look up EVM chains from https://chainid.network/chains.json
(community-maintained ethereum-lists/chains data).

Used as a fallback chain source for the `chain` command when a query
isn't found in the curated chains.yaml.
"""

import json
import os
import time

import requests

from peth.core.config import config

CHAINLIST_URL = "https://chainid.network/chains.json"
_CACHE_FILE = "chainid_network.json"
_CACHE_TTL_SEC = 24 * 3600

_memo = {"data": None}


def _cache_path() -> str:
    os.makedirs(config.cache_path, exist_ok=True)
    return os.path.join(config.cache_path, _CACHE_FILE)


def _read_cache():
    path = _cache_path()
    if not os.path.exists(path):
        return None, 0
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), os.path.getmtime(path)
    except (OSError, json.JSONDecodeError):
        return None, 0


def _write_cache(data):
    try:
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass


def _fetch_remote():
    r = requests.get(
        CHAINLIST_URL,
        headers={"User-Agent": "peth/chainlist"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_chainlist(force_refresh: bool = False):
    """
    Return list of chain dicts from chainid.network.

    Cached on disk for 24h; on network failure falls back to any cached copy.
    """
    if not force_refresh and _memo["data"] is not None:
        return _memo["data"]

    cached, mtime = _read_cache()
    fresh = cached is not None and (time.time() - mtime) < _CACHE_TTL_SEC

    if cached is not None and fresh and not force_refresh:
        _memo["data"] = cached
        return cached

    try:
        data = _fetch_remote()
        _write_cache(data)
        _memo["data"] = data
        return data
    except Exception as e:
        if cached is not None:
            _memo["data"] = cached
            return cached
        raise RuntimeError(f"Failed to fetch {CHAINLIST_URL}: {e}") from e


def find_chain(query):
    """
    Look up a chain by chainId (int / numeric string), shortName, or name.

    Match precedence: chainId > shortName (case-insensitive exact) >
    name (case-insensitive exact) > name (case-insensitive substring).
    """
    if query is None or query == "":
        return None

    chains = get_chainlist()

    if isinstance(query, int) or (isinstance(query, str) and query.isdigit()):
        cid = int(query)
        for c in chains:
            if c.get("chainId") == cid:
                return c
        return None

    q = str(query).lower()
    for c in chains:
        if c.get("shortName", "").lower() == q:
            return c
    for c in chains:
        if c.get("name", "").lower() == q:
            return c
    for c in chains:
        if q in c.get("name", "").lower():
            return c
    return None


def _candidate_rpcs(chain: dict):
    for url in chain.get("rpc", []) or []:
        if not isinstance(url, str):
            continue
        if "${" in url:
            continue
        if not url.startswith("https://"):
            continue
        yield url


def _probe_rpc(url: str, timeout: float = 4.0) -> bool:
    """
    Probe an RPC by issuing the same calls Web3Ex's init uses
    (``eth_chainId`` then ``eth_getBlockByNumber("latest")``); return
    True only if both succeed.
    """
    try:
        for payload in (
            {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_getBlockByNumber",
                "params": ["latest", False],
            },
        ):
            r = requests.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
            if r.status_code != 200:
                return False
            body = r.json()
            if not isinstance(body, dict) or "result" not in body or body.get("error"):
                return False
        return True
    except Exception:
        return False


def pick_rpc(chain: dict, probe: bool = True):
    """
    Pick the first usable HTTPS RPC URL with no ``${...}`` placeholder.

    When ``probe`` is True, each candidate is tested with ``eth_chainId``
    and the first one that responds is returned. Set ``probe=False`` to
    skip the network test (used by unit tests).
    """
    candidates = list(_candidate_rpcs(chain))
    if not candidates:
        return None
    if not probe:
        return candidates[0]
    for url in candidates:
        if _probe_rpc(url):
            return url
    return None


def pick_explorer(chain: dict):
    """Pick the best explorer URL (prefer EIP3091-standard explorers)."""
    explorers = chain.get("explorers") or []
    for e in explorers:
        if e.get("standard") == "EIP3091" and e.get("url"):
            return e["url"]
    for e in explorers:
        if e.get("url"):
            return e["url"]
    return None
