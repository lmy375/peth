({
    data: [],
    fault: function (log) {
    },
    step: function (log) {
        var topicCount = (log.op.toString().match(/LOG(\d)/) || [])[1];
        if (topicCount) {
            var start = log.stack.peek(0).valueOf();
            var size = log.stack.peek(1).valueOf();
            var res = {
                address: toHex(log.contract.getAddress()),
                data: toHex(log.memory.slice(start, start + size)),
            };
            res.topics = []
            for (var i = 0; i < topicCount; i++){
                res.topics.push('0x' + log.stack.peek(i+2).toString(16))
            }
                
            this.data.push(res);
        }
    },
    result: function () {
        return this.data;
    }
})