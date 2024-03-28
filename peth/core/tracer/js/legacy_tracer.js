({ 
    // For old version. no enter/exit/setup callback.
    config: {
        traceOp(opNumber){
            if (opNumber >= 0xA0 && opNumber <= 0xA4) return true; // LOG0~LOG4, See https://www.evm.codes/
            var opList = [
                0x20, // SHA3
                0x54, // SLOAD
                0x55, // SSTORE
                0x14, // EQ
                0x32, // ORIGIN
                0x33 // CALLER
            ]
            // Same as : if(opList.includes(opNumber)) return true;
            for(var i = 0; i< opList.length; i++){
                if (opList[i] == opNumber) return true;
            }
            
            return false;
        }
    },
    utils: {
        // For debug.
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
    _onNextStep(func){
        this.nextStepFunc = func;
    },

    _processStepToDo(log){
        if(this.nextStepFunc){
            this.nextStepFunc(log);
            this.nextStepFunc = null;
        }
    },
    // Called once on start.
    _setup(user_config) {
        if(this._setup_called){ // only once.
            return;
        }
        this._setup_called = true;

        this.utils.print("setup")

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
            if (!callObject.value) callObject.value = "0x0"

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
            return toHex(this.log.memory.slice(offset, end))
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

        this.utils.print("setup done");
    },

    // EVM error or REVERT.
    fault(log, db) {
        this.utils.print("fault(): " + log.getError());
        this._handleFaultLegacy(log, db)
    },

	descended: false,
    _handleFaultLegacy(log, db) {
		// If the topmost call already reverted, don't handle the additional fault again
		var call = this.logTree.cur();
        if (call.error !== undefined) { // fault by REVERT op.
			return;
		}
		call.error = log.getError();

		// Consume all available gas and clean any leftovers
		if (call.gas !== undefined) {
			call.gas = '0x' + bigInt(call.gas).toString(16);
			call.gasUsed = call.gas
		}
		delete call.gasIn; delete call.gasCost;
		delete call.outOff; delete call.outLen;

        this.logTree.onExitCall({
            error: log.getError()
        })
	},

	// from: https://github.com/bnb-chain/bsc/blob/master/eth/tracers/js/internal/tracers/call_tracer_legacy.js
	_handleCallLegacy(log, db) {
		// Capture any errors immediately
		var error = log.getError();
		if (error !== undefined) {
			this.fault(log, db);
			return;
		}
		// We only care about system opcodes, faster if we pre-check once
		var syscall = (log.op.toNumber() & 0xf0) == 0xf0;
		if (syscall) {
			var op = log.op.toString();
		}
		// If a new contract is being created, add to the call stack
		if (syscall && (op == 'CREATE' || op == "CREATE2")) {
			var inOff = log.stack.peek(1).valueOf();
			var inEnd = inOff + log.stack.peek(2).valueOf();

			// Assemble the internal call report and store for completion
			var call = {
				type:    op,
				from:    toHex(log.contract.getAddress()),
				input:   toHex(log.memory.slice(inOff, inEnd)),
				gasIn:   log.getGas(),
				gasCost: log.getCost(),
				value:   '0x' + log.stack.peek(0).toString(16)
			};
            this.logTree.onEnterCall(call)
			this.descended = true
			return;
		}
		// If a contract is being self destructed, gather that as a subcall too
		if (syscall && op == 'SELFDESTRUCT') {
			var callObject = {
				type:    op,
				from:    toHex(log.contract.getAddress()),
				to:      toHex(toAddress(log.stack.peek(0).toString(16))),
				gasIn:   log.getGas(),
				gasCost: log.getCost(),
				value:   '0x' + db.getBalance(log.contract.getAddress()).toString(16)
			};
            this.logTree.onEnterCall(callObject)
			return
		}
		// If a new method invocation is being done, add to the call stack
		if (syscall && (op == 'CALL' || op == 'CALLCODE' || op == 'DELEGATECALL' || op == 'STATICCALL')) {
			// Skip any pre-compile invocations, those are just fancy opcodes
			var to = toAddress(log.stack.peek(1).toString(16));
			if (isPrecompiled(to)) {
				return
			}
			var off = (op == 'DELEGATECALL' || op == 'STATICCALL' ? 0 : 1);

			var inOff = log.stack.peek(2 + off).valueOf();
			var inEnd = inOff + log.stack.peek(3 + off).valueOf();

			// Assemble the internal call report and store for completion
			var call = {
				type:    op,
				from:    toHex(log.contract.getAddress()),
				to:      toHex(to),
				input:   toHex(log.memory.slice(inOff, inEnd)),
				gasIn:   log.getGas(),
				gasCost: log.getCost(),
				outOff:  log.stack.peek(4 + off).valueOf(),
				outLen:  log.stack.peek(5 + off).valueOf()
			};
			if (op != 'DELEGATECALL' && op != 'STATICCALL') {
				call.value = '0x' + log.stack.peek(2).toString(16);
			}
			this.logTree.onEnterCall(call);
			this.descended = true;
			return;
		}
		// If we've just descended into an inner call, retrieve it's true allowance. We
		// need to extract if from within the call as there may be funky gas dynamics
		// with regard to requested and actually given gas (2300 stipend, 63/64 rule).
		if (this.descended) {
			if (log.getDepth() >= this.logTree.callstack.length) {
				this.logTree.cur().gas = log.getGas();
			} else {
				// TODO(karalabe): The call was made to a plain account. We currently don't
				// have access to the true gas amount inside the call and so any amount will
				// mostly be wrong since it depends on a lot of input args. Skip gas for now.
			}
			this.descended = false;
		}
		// If an existing call is returning, pop off the call stack
		if (syscall && op == 'REVERT') {
			this.logTree.cur().error = "execution reverted";
			return;
		}
		if (log.getDepth() == this.logTree.callstack.length) { // Just exits from a call.
            // Do onExitCall thing.

			// Pop off the last call and get the execution results
			var call = this.logTree.callstack.pop();

			if (call.type == 'CREATE' || call.type == "CREATE2") {
				// If the call was a CREATE, retrieve the contract address and output code
				call.gasUsed = '0x' + bigInt(call.gasIn - call.gasCost - log.getGas()).toString(16);
				delete call.gasIn; delete call.gasCost;

				var ret = log.stack.peek(0);
				if (!ret.equals(0)) {
					call.to     = toHex(toAddress(ret.toString(16)));
					call.output = toHex(db.getCode(toAddress(ret.toString(16))));
				} else if (call.error === undefined) {
					call.error = "internal failure"; // TODO(karalabe): surface these faults somehow
				}
			} else {
				// If the call was a contract call, retrieve the gas usage and output
				if (call.gas !== undefined) {
					call.gasUsed = '0x' + bigInt(call.gasIn - call.gasCost + call.gas - log.getGas()).toString(16);
				}
				var ret = log.stack.peek(0);
				if (!ret.equals(0)) {
					call.output = toHex(log.memory.slice(call.outOff, call.outOff + call.outLen));
				} else if (call.error === undefined) {
					call.error = "internal failure"; // TODO(karalabe): surface these faults somehow
				}
				delete call.gasIn; delete call.gasCost;
				delete call.outOff; delete call.outLen;
			}
			if (call.gas !== undefined) {
				call.gas = '0x' + bigInt(call.gas).toString(16);
			}
		}
	},

    _handleOp(opNumber, log){
        rawlog = log.log;
        rawdb = log.db;
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
            this._onNextStep(function(log){
                this.utils.assert(this.lastOpNum == 0x20);
                item.hash = log.peekHex(0);
                this.logTree.addLog(item);
            })
        }


        if (opNumber == 0x54){ // SLOAD
            var key = log.peekHex(0);
            this._onNextStep(function(log){
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
            this._onNextStep(function(log){
                this.utils.assert(this.lastOpNum == 0x32);
                this.logTree.addLog({
                    logType: 'origin',
                    origin: log.peekHex(0)
                })
            })
        }

        if (opNumber == 0x33){ // CALLER
            this._onNextStep(function(log){
                this.utils.assert(this.lastOpNum == 0x33);
                this.logTree.addLog({
                    logType: 'caller',
                    caller: log.peekHex(0)
                })
            })
        }
    },


    // Called on EVM step.
    step(rawlog, rawdb) {
        this._setup();
        
        // Capture any errors immediately
        // Copied from call_tracer_legacy.js, but no idea when this happens: revert step doesn't set error here.
        var error = rawlog.getError();
        if (error !== undefined) {
            this.utils.print("step(): error catched.");
            this.fault(rawlog, rawdb);
            return;
        }
        
        var contract = toHex(rawlog.contract.getAddress());
        this.utils.print("step ["+rawlog.getDepth()+"-"+ contract.substr(0, 8)+'-' + rawlog.getPC() + "] " + rawlog.op.toString());

        // Better API.
        log = this.wrapLog(rawlog, rawdb);


        this._processStepToDo(log);

        this._handleCallLegacy(rawlog, rawdb);
    
        var opNumber = log.getOpNumber();
        if (this.config.traceOp(opNumber)){
            this._handleOp(opNumber, log);  
        }


        this.lastOpNum = opNumber;
    },


    // Called on tracer exits.
    result(ctx, db) {
        // Set root tx info.
        var tx;
        if (this.logTree){
            tx = this.logTree.root;
        }else{
            tx = {} // ETH transfer.
        }
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
        tx.time = ctx.time ? ctx.time.replace('µ', 'u'): ctx.time;
        tx.gas =  ctx.gas
        tx.gasUsed =ctx.gasUsed
        tx.gasPrice = ctx.gasPrice;
        tx.type = ctx.type;
        tx.value = (ctx.value? '0x' + ctx.value.toString(16): "0x0");
        tx.block = ctx.block;
        tx.intrinsicGas = ctx.intrinsicGas

        if (this.utils.debug) {
            // this.utils.print(JSON.stringify(tx, 0, 2));
            return "debug message:\n" + this.utils.tracerLogMsg; // return all print msg.
        }
        return tx;
    }
})