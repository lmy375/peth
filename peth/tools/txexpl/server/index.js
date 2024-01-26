(function(){
    let url = "http://localhost:8000/explain_url?url=" + escape(location.href)
    open(url);
})()