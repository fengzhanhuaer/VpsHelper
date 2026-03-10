export namespace conntrack {
	
	export class Connection {
	    pid: number;
	    procName: string;
	    protocol: string;
	    localAddr: string;
	    remoteAddr: string;
	    state: string;
	
	    static createFrom(source: any = {}) {
	        return new Connection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.procName = source["procName"];
	        this.protocol = source["protocol"];
	        this.localAddr = source["localAddr"];
	        this.remoteAddr = source["remoteAddr"];
	        this.state = source["state"];
	    }
	}

}

