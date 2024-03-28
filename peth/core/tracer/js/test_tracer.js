({
    config: {
        traceOp(opNumber){
            if (opNumber >= 0xA0 && opNumber <= 0xA4) return true; // LOG0~LOG4, See https://www.evm.codes/
            // var opList = [
            //     0x20, // SHA3
            //     0x54, // SLOAD
            //     0x55, // SSTORE
            //     0x14, // EQ
            //     0x32, // ORIGIN
            //     0x33 // CALLER
            // ]
            // // Same as : if(opList.includes(opNumber)) return true;
            // for(var i = 0; i< opList.length; i++){
            //     if (opList[i] == opNumber) return true;
            // }
            
            return false;
        }
    },
    utils: {
        // For debug.
    
        // debug: true,
        debug: false,

        tracerLogMsg: "",
        print(msg) {
            if (this.debug) this.tracerLogMsg += msg + "\n";
        },
        assert(condition, msg){
            if (!condition) throw new Error("Assert: "+ msg);
        },
        getStack(){
            return (new Error()).stack
        }
    },

    //-------

    // globals.
    logTree: null,
    lastOpNum: null,
    nextStepFunc: null,
    onNextStep(func){
        this.nextStepFunc = func;
    },

    processStepToDo(log){
        if(this.nextStepFunc){
            this.nextStepFunc(log);
            this.nextStepFunc = null;
        }
    },
    // Called once on start.
    setup(user_config) {
        if(this._setup_called){ // only once.
            return;
        }
        this._setup_called = true;

        function LogTree() {
            this.callstack = [];
            this.root = {
                logType: "call",
                logs: []
            };
        }

        // Current call node.
        LogTree.prototype.cur = function () {
            var depth = this.callstack.length;
            if (depth == 0) {
                return this.root;
            } else {
                return this.callstack[depth - 1];
            }
        }

        LogTree.prototype.onEnterCall = function (callObject) {
            var cur = this.cur();

            callObject.logType = "call";
            callObject.logs = []; // for sub calls and events.

            cur.logs.push(callObject);
            this.callstack.push(callObject);
        }

        LogTree.prototype.onExitCall = function (callResult) {
            var cur = this.cur();
            cur.gasUsed = callResult.gasUsed;
            cur.output = callResult.output;
            cur.error = callResult.error;
            cur.reverted = !!cur.error; // to boolean.
            this.callstack.pop();
        }

        LogTree.prototype.addLog = function (item) {
            var cur = this.cur();
            cur.logs.push(item);
        }

        this.logTree = new LogTree();

        function LogWrapper(log, db){
            this.log = log;
            this.db = db;
        }

        LogWrapper.prototype.getOpNumber = function(){
            return this.log.op.toNumber();
        }

        LogWrapper.prototype.peekInt = function(offset){
            return this.log.stack.peek(offset).valueOf();
        }

        LogWrapper.prototype.peekHex = function(offset){
            return '0x' + this.log.stack.peek(offset).toString(16);
        }

        LogWrapper.prototype.peekWord = function(offset){
            return toWord(this.log.stack.peek(offset).toString(16));
        }

        LogWrapper.prototype.readMem = function(offset, size){
            var end = offset + size;
            var mem_size = this.log.memory.length();
            if (end > mem_size){
                end = mem_size;
            }
            if(offset > mem_size){
                return '0x'.padEnd(2*size, '0')
            }
            // Pad zero to total length. first 2 for pre '0x'
            return toHex(this.log.memory.slice(offset, end)).padEnd(2+size*2, '0')
        }

        LogWrapper.prototype.readMemByIndex = function(offset_idx, size_idx){
            var offset = this.peekInt(offset_idx);
            var size = this.peekInt(size_idx);
            return this.readMem(offset, size);
        }

        LogWrapper.prototype.getContract = function(){
            return toHex(this.log.contract.getAddress())
        }

        this.wrapLog = function(log, db){
            return new LogWrapper(log, db)
        }
    },

    // EVM error or REVERT.
    fault(log, db) {
        this.utils.print("fault(): " + log.getError());
    },

    // Called on internal tx start.
    enter(frame) {
        var callObject = {
            type: frame.getType(),
            from: toHex(frame.getFrom()),
            to: toHex(frame.getTo()),
            value: frame.getValue()? '0x' + bigInt(frame.getValue()).toString(16): "0x0",
            input: toHex(frame.getInput()),
            gas: '0x' + bigInt(frame.getGas()).toString('16')
        }
        this.logTree.onEnterCall(callObject);


        // debug
        // var msg = callObject.type + " " +
        //     callObject.from +
        //     "->" +
        //     callObject.to +
        //     "(" + callObject.value + ") " + callObject.input;
        // this.utils.print(msg);
    },

    // Called on internal tx exit.
    exit(result) {
        var callResult = {
            gasUsed: result.getGasUsed(),
            output: toHex(result.getOutput()),
            error: (result.getError() || null)
        }

        this.logTree.onExitCall(callResult);

        // debug
        // var msg = callResult.gasUsed + " " + callResult.output + " " + callResult.error;
        // this.utils.print(msg);
    },


    // Called on EVM step.
    step(rawlog, rawdb) {
        // Capture any errors immediately
        // Copied from call_tracer_legacy.js, but no idea when this happens: revert step doesn't set error here.
        var error = rawlog.getError();
        if (error !== undefined) {
            this.utils.print("step(): error catched.");
            this.fault(rawlog, rawdb);
            return;
        }
        
        // var contract = toHex(rawlog.contract.getAddress());
        // this.utils.print("step ["+rawlog.getDepth()+"-"+ contract.substr(0, 8)+'-' + rawlog.getPC() + "] " + rawlog.op.toString());


        // Better API.
        log = this.wrapLog(rawlog, rawdb);

        this.processStepToDo(log);

    
        var opNumber = log.getOpNumber();

        if (this.config.traceOp(opNumber)){
            if (opNumber >= 0xA0 && opNumber <= 0xA4) { // LOG0~LOG4, See https://www.evm.codes/
                var topicCount = opNumber - 0xA0;
                var event = {
                    logType: "event",
                    address: log.getContract(),
                    topics: [],
                    data: log.readMemByIndex(0, 1)
                };
                for (var i = 0; i < topicCount; i++) {
                    event.topics.push(log.peekHex(i+2));
                }
                this.logTree.addLog(event);
            }

            if (opNumber == 0x20) { // SHA3
                var item = {
                    logType: "sha3",
                    data: log.readMemByIndex(0, 1)
                }
                this.onNextStep(function(log){
                    this.utils.assert(this.lastOpNum == 0x20);
                    item.hash = log.peekHex(0);
                    this.logTree.addLog(item);
                })
            }


            if (opNumber == 0x54){ // SLOAD
                var key = log.peekHex(0);
                this.onNextStep(function(log){
                    this.utils.assert(this.lastOpNum == 0x54);
                    this.logTree.addLog({
                        logType: 'sload',
                        key: key,
                        value: log.peekHex(0)
                    })
                })
            }

            if (opNumber == 0x55){ // SSTORE
                var key = log.peekHex(0);
                var newValue = log.peekHex(1);

                // https://github.com/ethereum/go-ethereum/blob/master/eth/tracers/js/internal/tracers/prestate_tracer_legacy.js
                var addr = rawlog.contract.getAddress();
                var slot = toWord(rawlog.stack.peek(0).toString(16));
                var oldValue = toHex(rawdb.getState(addr, slot));

                this.logTree.addLog({
                    logType: 'sstore',
                    key: key,
                    oldValue: oldValue,
                    newValue: newValue
                })
            }

            if (opNumber == 0x14){ // EQ
                var v1 = log.peekHex(0);
                var v2 = log.peekHex(1);
                this.logTree.addLog({
                    logType: 'eq',
                    v1: v1,
                    v2: v2
                })
            }

            if (opNumber == 0x32){ // ORIGIN
                this.onNextStep(function(log){
                    this.utils.assert(this.lastOpNum == 0x32);
                    this.logTree.addLog({
                        logType: 'origin',
                        origin: log.peekHex(0)
                    })
                })
            }

            if (opNumber == 0x33){ // CALLER
                this.onNextStep(function(log){
                    this.utils.assert(this.lastOpNum == 0x33);
                    this.logTree.addLog({
                        logType: 'caller',
                        caller: log.peekHex(0)
                    })
                })
            }
        }

        this.lastOpNum = opNumber;
    },


    // Called on tracer exits.
    result(ctx, db) {
        // Set root tx info.
        var tx = this.logTree.root;
        tx.from = toHex(ctx.from);
        tx.error = ctx.error;

        // Invalid in debug_TraceCall
        tx.blockHash = ctx.blockHash !== undefined? toHex(ctx.blockHash): "0x";
        tx.txIndex = ctx.txIndex !== undefined? ctx.txIndex: 0;
        tx.txHash = ctx.txHash !== undefined? toHex(ctx.txHash): "0x";

        // ??? 
        // if `to` not set in debug_traceCall request.
        // this will be "0x002173ee04833ba62cf8a6ef47e7622a0facdf71" 
        tx.to = toHex(ctx.to);
        tx.input = toHex(ctx.input);
        tx.output = toHex(ctx.output);

        // Remove non-ascii code to ensure that no '\ufeff' prefix in our result.
        tx.time = ctx.time.replace('µ', 'u');;
        tx.gas =  ctx.gas
        tx.gasUsed =ctx.gasUsed
        tx.gasPrice = ctx.gasPrice;
        tx.type = ctx.type;
        tx.value = (ctx.value? '0x' + ctx.value.toString(16): "0x0");
        tx.block = ctx.block;
        tx.intrinsicGas = ctx.intrinsicGas

        if (this.config.debug) {
            this.utils.print(JSON.stringify(tx, 0, 2));
            return "debug message:\n" + this.utils.tracerLogMsg; // return all print msg.
        }
        return tx;
    }
})