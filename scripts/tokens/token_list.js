

function download(filename, file_content){
    var blob = new Blob([file_content], { type: 'text/json;charset=utf-8;' });
    var link = document.createElement("a");
    // Browsers that support HTML5 download attribute
    var url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function etherscan(){
    // https://etherscan.io/tokens
    // https://bscscan.com/tokens
    // https://polygonscan.com/tokens
    // https://ftmscan.com/tokens
    // https://era.zksync.network/tokens
    let result = []
    let tokens = $('#ContentPlaceHolder1_tblErc20Tokens#ContentPlaceHolder1_tblErc20Tokens > table > tbody')[0]
    for (let token of tokens.children){
        let url = token.children[1].getElementsByTagName('a')[0].href
        let address = url.substr(-42)
        let [name, symbol] = token.children[1].innerText.split('\n')
        symbol = symbol.substr(1, symbol.length-2)
        let price = token.children[2].children[0].dataset.bsTitle
        price = parseFloat(price.substr(1).replace(',', ''))
        result.push({symbol, address, url, name, price})
    }
    download('tokens.json', JSON.stringify(result))
    console.log(result)
}

function opscan(){
    // https://optimistic.etherscan.io/tokens
    // https://basescan.org/tokens
    // https://arbiscan.io/tokens
    let result = []
    let tokens = $('#tblResult > tbody')[0]
    for (let token of tokens.children){
        let url = token.children[1].getElementsByTagName('a')[0].href
        let address = url.substr(-42)
        let nameSymbol = token.children[1].innerText.split('\n')[0]
        let name = nameSymbol.substr(0, nameSymbol.lastIndexOf('(')).trim()
        let symbol = nameSymbol.substr(nameSymbol.lastIndexOf('('))
        symbol = symbol.substr(1, symbol.length-2)

        let price = token.children[2].children[0].dataset.title
        price = parseFloat(price.substr(1).replace(',', ''))
        result.push({symbol, address, url, name, price})
    }
    download('tokens.json', JSON.stringify(result))
    console.log(result)
}

function avaxsnowtrace(){
    // https://snowtrace.io/tokens
    let result = []
    let tokens = $('#tokenserc20 > div > div > div.bg-v2 > div > div > div.tbody')[0]
    for (let token of tokens.children){
        let cols = token.getElementsByClassName('td')
        let a = cols[2].getElementsByTagName('a')[0]
        let url = a.href
        let address = /0x[0-9a-fA-F]{40}/.exec(url)[0]

        let nameSymbol = a.innerText
        let name = nameSymbol.substr(0, nameSymbol.lastIndexOf('(')).trim()
        let symbol = nameSymbol.substr(nameSymbol.lastIndexOf('('))
        symbol = symbol.substr(1, symbol.length-2)

        let price;
        if (cols[3].innerHTML.includes('<sub>')){
            price = "$0.0000001" // too small
        } else{
            price = cols[3].innerText.split('\n')[0]
        }
        price = parseFloat(price.substr(1).replace(',', ''))
        result.push({symbol, address, url, name, price})
    }
    download('tokens.json', JSON.stringify(result))
    console.log(result)
}