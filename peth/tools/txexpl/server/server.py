import os
import re

from typing import Union

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..txexpl import TxExplainer


def parse_url_tx(url):
    r = re.findall("[0-9a-fA-F]{64}", url)
    if not r:
        return "txid not found"
    
    txid = r[0]
    chain = None
    if 'etherscan' in url:
        chain = 'eth'
    elif 'bscscan' in url:
        chain = 'bsc'
    elif 'snowtrace' in url:
        chain = 'avax'
    elif 'polygonscan' in url:
        chain = 'matic'
    elif 'optimistic' in url:
        chain = 'op'
    elif 'arbiscan' in url:
        chain = 'arb'
    
    if chain is None:
        return "chain not found"
    
    txe = TxExplainer(chain)

    tx = txe.peth.web3.eth.get_transaction(txid)
    to = tx["to"]
    data = tx["input"]

    if len(data) <= 8 + 2:
        return f"Calldata too short. length:{len(data)}"

    s = txe.explain_call(to, data)
    if s is None:
        s = "No pattern found for this tx."
    
    s += "\n\n----------------\n"

    func = None
    try:
        func = txe.pattern_abi._get_function_by_calldata(data)
    except Exception as e:
        func = txe.peth.get_function(to, None, data)

    if func:
        s += "**%s**\n" % func.full
        value_map = txe.decode_tx(txid)
        s += txe.value_map_to_md(value_map)
    return s

PWD = os.path.dirname(__file__)

INDEX = os.path.join(PWD, "index.html")
INDEX_DATA = open(INDEX).read()

MD = os.path.join(PWD, "markdown.html")
MD_DATA = open(INDEX).read()

JS = os.path.join(PWD, "index.js")
JS_DATA = open(JS).read()

app = FastAPI()

# Enable CORS for all routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", response_class=HTMLResponse)
def index():
    return open(INDEX).read()

@app.get("/markdown.html", response_class=HTMLResponse)
def markdown(url):
    msg = parse_url_tx(url)
    msg = msg.replace('`', '\\`')
    return open(MD).read().replace("#MARKDOWN", str(msg))

@app.get("/index.js")
def index_js():
    return Response(content=open(JS).read(), media_type="text/javascript")

@app.get("/explain", response_class=HTMLResponse)
def explain(url):
    return parse_url_tx(url)
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)