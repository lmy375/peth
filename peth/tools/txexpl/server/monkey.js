// ==UserScript==
// @name         Tx Explainer
// @namespace    http://tampermonkey.net/
// @version      2024-01-26
// @description  try to take over the world!
// @author       You
// @match        */*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        none
// ==/UserScript==

(function() {
    'use strict';
    const ethereum = window.ethereum;
    if (!ethereum) return; // Not a web3 site.
    const CHAIN_ID_MAP = {
        "0x1": "eth",
        "0x38": "bsc",
        "0xa4b1": "arb",
        "0x89": "matic",
        "0xa": "op",
        "0xa86a": "avax"
    };

    const oriRequest = ethereum.request;

    function getChainName(chainId){
        const chain = CHAIN_ID_MAP[chainId];
        if(!chain) alert(`unknown chain for ${chainId}`);
        return chain;
    }
    async function getChain(){
        const chainId = await oriRequest({
                    "method": "eth_chainId",
                    "params": []
        });
        return getChainName(chainId)
    }

    function openTxExpPage(chain, to, data, value){
        const url = `http://localhost:8000/explain_call?chain=${chain}&to=${to}&data=${data}&value=${value}`;
        console.log(url);
        open(url);
    }

    ethereum.request = async function (req) {
        console.log("ethereum.request req:", req);

        try {
            if (req.method == "eth_sendTransaction") {
                const tx = req.params[0]
                const to = tx.to;
                const data = tx.data;
                const value = tx.value ? window.BigInt(tx.value).toString() : "0"; // NOTE: this is a string value.
                const chain = await getChain();
                openTxExpPage(chain, to, data, value);
            } else if (req.method == "eth_signTypedData_v4"){
                const typedData = JSON.parse(req.params[1]);
                if (typedData.primaryType == 'SafeTx'){
                    const chainId = '0x' + parseInt(typedData.domain.chainId).toString(16);
                    const chain = getChainName(chainId);
                    const to = typedData.message.to;
                    const data = typedData.message.data;
                    const value = typedData.message.value;
                    openTxExpPage(chain, to, data, value);
                }
            }
        } catch (e) {
            console.error("hooking ethereum.request error", e);
            alert('hooking ethereum.request error ' + e);
        }

        const ret = await oriRequest(req);
        console.log("ethereum.request ret:", ret)
        return ret;
    }
    console.log("ethereum.request hooked.");
})();