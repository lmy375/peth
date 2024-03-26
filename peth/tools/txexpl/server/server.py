import os
import re

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from ..txexpl import Peth, TxExplainer


def parse_url_tx(url):
    r = re.findall("[0-9a-fA-F]{64}", url)
    if not r:
        return "txid not found"

    txid = r[0]
    chain = None
    if "optimistic" in url:  # Should before etherscan check.
        chain = "op"
    elif "etherscan" in url:
        chain = "eth"
    elif "bscscan" in url:
        chain = "bsc"
    elif "snowtrace" in url:
        chain = "avax"
    elif "polygonscan" in url:
        chain = "matic"
    elif "arbiscan" in url:
        chain = "arb"

    if chain is None:
        return "chain not found"

    _switch_chain(chain)
    return txe.gen_full_md_from_txid(txid)


PWD = os.path.dirname(__file__)

INDEX_PATH = os.path.join(PWD, "index.html")
INDEX_DATA = open(INDEX_PATH).read()

MD_PATH = os.path.join(PWD, "markdown.html")
MD_DATA = open(MD_PATH).read()

JS_PATH = os.path.join(PWD, "index.js")
JS_DATA = open(JS_PATH).read()

app = FastAPI()

# Enable CORS for all routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

txe = TxExplainer("eth")


def _switch_chain(chain):
    if txe.peth.chain != chain:
        txe.peth = Peth.get_or_create(chain)


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_DATA


@app.get("/index.js")
def index_js():
    return Response(content=JS_DATA, media_type="text/javascript")


@app.get("/explain_url", response_class=HTMLResponse)
def explain_url(url):
    msg = parse_url_tx(url)
    msg = msg.replace("`", "\\`")
    return MD_DATA.replace("#MARKDOWN", str(msg))


@app.get("/explain_txid", response_class=HTMLResponse)
def explain_txid(chain, txid):
    _switch_chain(chain)
    msg = txe.gen_full_md_from_txid(txid)
    msg = msg.replace("`", "\\`")
    return MD_DATA.replace("#MARKDOWN", str(msg))


@app.get("/explain_call", response_class=HTMLResponse)
def explain_call(chain, to, data, value=0):
    _switch_chain(chain)
    msg = txe.gen_full_md_from_call(to, data, value)
    msg = msg.replace("`", "\\`")
    return MD_DATA.replace("#MARKDOWN", str(msg))


def main():
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
