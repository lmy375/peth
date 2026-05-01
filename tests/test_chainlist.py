from peth.core import chainlist

FIXTURE = [
    {
        "name": "Ethereum Mainnet",
        "chainId": 1,
        "shortName": "eth",
        "rpc": [
            "https://mainnet.infura.io/v3/${INFURA_API_KEY}",
            "https://eth.drpc.org",
        ],
        "explorers": [
            {"name": "etherscan", "url": "https://etherscan.io", "standard": "EIP3091"}
        ],
    },
    {
        "name": "Polygon Mainnet",
        "chainId": 137,
        "shortName": "matic",
        "rpc": ["https://polygon-rpc.com"],
        "explorers": [
            {
                "name": "polygonscan",
                "url": "https://polygonscan.com",
                "standard": "EIP3091",
            }
        ],
    },
    {
        "name": "No Rpc Chain",
        "chainId": 999999,
        "shortName": "norpc",
        "rpc": ["https://x.example/${KEY}"],
        "explorers": [],
    },
]


def _patch(monkeypatch):
    chainlist._memo["data"] = None
    monkeypatch.setattr(chainlist, "get_chainlist", lambda force_refresh=False: FIXTURE)


def test_find_by_chain_id_int(monkeypatch):
    _patch(monkeypatch)
    assert chainlist.find_chain(137)["shortName"] == "matic"


def test_find_by_chain_id_str(monkeypatch):
    _patch(monkeypatch)
    assert chainlist.find_chain("137")["shortName"] == "matic"


def test_find_by_short_name(monkeypatch):
    _patch(monkeypatch)
    assert chainlist.find_chain("matic")["chainId"] == 137


def test_find_by_name_case_insensitive(monkeypatch):
    _patch(monkeypatch)
    assert chainlist.find_chain("Polygon Mainnet")["chainId"] == 137


def test_find_by_name_substring(monkeypatch):
    _patch(monkeypatch)
    assert chainlist.find_chain("polygon")["chainId"] == 137


def test_find_missing(monkeypatch):
    _patch(monkeypatch)
    assert chainlist.find_chain("does-not-exist") is None


def test_pick_rpc_skips_placeholder():
    eth = FIXTURE[0]
    assert chainlist.pick_rpc(eth, probe=False) == "https://eth.drpc.org"


def test_pick_rpc_returns_none_when_all_templated():
    norpc = FIXTURE[2]
    assert chainlist.pick_rpc(norpc, probe=False) is None


def test_pick_rpc_probes_and_picks_first_working(monkeypatch):
    chain = {
        "rpc": [
            "https://dead.example/rpc",
            "https://alive.example/rpc",
            "https://later.example/rpc",
        ]
    }
    monkeypatch.setattr(
        chainlist, "_probe_rpc", lambda url, timeout=4.0: "alive" in url
    )
    assert chainlist.pick_rpc(chain) == "https://alive.example/rpc"


def test_pick_rpc_returns_none_when_all_dead(monkeypatch):
    chain = {"rpc": ["https://a.example", "https://b.example"]}
    monkeypatch.setattr(chainlist, "_probe_rpc", lambda url, timeout=4.0: False)
    assert chainlist.pick_rpc(chain) is None


def test_pick_explorer_eip3091():
    assert chainlist.pick_explorer(FIXTURE[1]) == "https://polygonscan.com"


def test_pick_explorer_none_when_empty():
    assert chainlist.pick_explorer(FIXTURE[2]) is None
