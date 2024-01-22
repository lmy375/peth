(async function(){ // Execute on the target site.

    let fetchStyle = function(url) {
        return new Promise((resolve, reject) => {
          let link = document.createElement('link');
          link.type = 'text/css';
          link.rel = 'stylesheet';
          link.onload = () => resolve();
          link.onerror = () => reject();
          link.href = url;
          document.head.appendChild(link);
        });
    };

    let fetchScript = function(url){
        return new Promise((resolve, reject) => {
            let js = document.createElement("script");
            js.type = "text/javascript";
            js.src = url;
            js.onload = resolve;
            js.onerror = reject;
            document.head.appendChild(js);
          });
    };

    let initModal = function(){
        let d = document.createElement("div");
        d.innerHTML = `
            <div id="tx_modal" class="ui modal">
                <i class="close icon"></i>
                <div class="header">
                    Transaction
                </div>
            
                <div id="tx_detail" class="content">
                </div>
            </div>
        </div>
        `
        document.body.appendChild(d);
    }

    await fetchStyle("https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.1.8/semantic.css");
    await fetchScript("https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js");
    await fetchScript("https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.1.8/semantic.min.js");
    
    await fetchScript("https://cdn.jsdelivr.net/npm/marked/marked.min.js");
    
    if($('#tx_modal').length == 0) initModal();

    const URL = location.href;
    const TX_REGEXP = /[0-9A-Fa-f]{64}/;

    const MARKDOWN = `
# Marked in the browser
Rendered by **marked**
[this is a link]()
- a
- b
`

    $('#tx_modal').modal('show');
    $("#tx_detail").html(
        marked.parse(MARKDOWN)
    )
    
})();


