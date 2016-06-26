var BigInt = require('./BigInteger/BigInteger.js');
var struct = require('./pack/bufferpack.js');
var SHA = require('./SHA/src/sha.js');
var zlib = require('./zlib/bin/node-zlib.js');

function p2p() {
    "use strict";
    var m = this;

    if (!Array.prototype.last) {
        Array.prototype.last = function() {
            return this[this.length - 1];
        };
    }

    m.version = "0.2.1";
    m.build_num = "build.117"
    m.compression = ['gzip'];

    // User salt generation pulled from: http://stackoverflow.com/a/2117523
    m.user_salt = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random()*16|0, v = c === 'x' ? r : (r&0x3|0x8);
        return v.toString(16);
    });

    m.base_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    m.to_base_58 = function(i) {
        //Takes an integer and returns its corresponding base_58 string
        var string = "";
        if (!BigInt.isInstance(i)) {
            i = BigInt(i);
        }
        while (i.notEquals(0)) {
            string = m.base_58[i.mod(58)] + string;
            i = i.divide(58);
        }
        return string;
    };


    m.from_base_58 = function(string) {
        //Takes a base_58 string and returns its corresponding integer
        var decimal = BigInt(0);
        //for char in string {
        for (var i = 0; i < string.length; i++) {
            decimal = decimal.times(58).plus(m.base_58.indexOf(string[i]));
        }
        return decimal;
    };


    m.getUTC = function() {
        return Math.floor(Date.now() / 1000);
    };


    m.SHA384 = function(text) {
        var hash = new SHA("SHA-384", "TEXT");
        hash.update(text);
        return hash.getHash("HEX");
    };


    m.SHA256 = function(text) {
        var hash = new SHA("SHA-256", "TEXT");
        hash.update(text);
        return hash.getHash("HEX");
    };


    m.compress = function(text, method) {
        if (method === "gzip") {
            return zlib.deflateSync(Buffer(text));
        }
        else {
            throw "Unknown compression method";
        }
    };


    m.decompress = function(text, method) {
        if (method === "gzip") {
            return zlib.inflateSync(Buffer(text));
        }
        else {
            throw "Unknown compression method";
        }
    };


    m.protocol = class protocol {
        constructor(subnet, encryption) {
            this.subnet = subnet;
            this.encryption = encryption;
        }

        id() {
            var protocol_hash = m.SHA256([this.subnet, this.encryption, m.version].join(''));
            return m.to_base_58(BigInt(protocol_hash, 16));
        }
    };

    m.default_protocol = new m.protocol('', 'Plaintext');

    m.pathfinding_message = class pathfinding_message {
        constructor(protocol, msg_type, sender, payload, compression) {
            this.protocol = protocol
            this.msg_type = msg_type
            this.sender = sender
            this.payload = payload
            this.time = m.getUTC()
            if (compression) {
                this.compression = compression
            }
            else {
                this.compression = []
            }
            this.compression_fail = false
        }

        static feed_string(protocol, string, sizeless, compressions) {
            string = m.pathfinding_message.sanitize_string(string, sizeless)
            var compression_return = m.pathfinding_message.decompress_string(string, compressions)
            var compression_fail = compression_return[1]
            string = compression_return[0]
            var packets = m.pathfinding_message.process_string(string)
            var msg = new m.pathfinding_message(protocol, packets[0], packets[1], packets.slice(4), compressions)
            msg.time = m.from_base_58(packets[3])
            msg.compression_fail = compression_fail
            return msg
        }

        static sanitize_string(string, sizeless) {
            if (!sizeless) {
                if (struct.unpack("!L", Buffer(string.substring(0,4)))[0] !== string.substring(4).length) {
                    throw "The following expression must be true: struct.unpack(\"!L\", Buffer(string.substring(0,4)))[0] === string.substring(4).length"
                }
                string = string.substring(4)
            }
            return string
        }

        static decompress_string(string, compressions) {
            var compression_fail = false
            compressions = compressions || []
            for (var i = 0; i < compressions.length; i++) {
                if (compressions[i] in m.compression) {  // module scope compression
                    console.log("Trying %s compression" % method)
                    try {
                        string = m.decompress(string, method)
                        compression_fail = false
                        break
                    }
                    catch(err) {
                        compression_fail = true
                        continue
                    }
                }
            }
            return [string, compression_fail]
        }

        static process_string(string) {
            var processed = 0
            var expected = string.length
            var pack_lens = []
            var packets = []
            function add(a, b) {
                return a + b
            }
            while (processed !== expected) {
                pack_lens = pack_lens.concat(struct.unpack("!L", Buffer(string.substring(processed, processed+4))))
                processed += 4
                expected -= pack_lens.last()
            }
            // Then reconstruct the packets
            for (var i=0; i < pack_lens.length; i++) {
                var start = processed + pack_lens.slice(0, i).reduce(add, 0)
                var end = start + pack_lens[i]
                packets = packets.concat([string.substring(start, end)])
            }
            return packets
        }

        get compression_used() {
            for (var i = 0; i < m.compression.length; i++) {
                for (var j = 0; j < this.compression.length; j++) {
                    if (m.compression[i] === this.compression[j]) {
                        return m.compression[i]
                    }
                }
            }
            return null
        }

        get time_58() {
            return m.to_base_58(this.time)
        }

        get id() {
            var payload_string = this.payload.join('')
            var payload_hash = m.SHA384(payload_string + this.time_58)
            return m.to_base_58(BigInt(payload_hash, 16))
        }

        get packets() {
            var meta = [this.msg_type, this.sender, this.id, this.time_58]
            return meta.concat(this.payload)
        }

        get __non_len_string() {
            var string = this.packets.join('')
            var headers = []
            for (var i = 0; i < this.packets.length; i++) {
                headers = headers.concat(struct.pack("!L", [this.packets[i].length]))
            }
            string = headers.join('') + string
            if (this.compression_used) {
                string = m.compress(string, this.compression_used)
            }
            return string
        }
        
        get string() {
            var string = this.__non_len_string
            return struct.pack("!L", [string.length]) + string
        }

        get length() {
            return this.__non_len_string.length
        }

        len() {
            return struct.pack("!L", [this.length])
        }
    }
}

if( typeof exports !== 'undefined' ) {
    if( typeof module !== 'undefined' && module.exports ) {
        exports = module.exports = new p2p()
    }
    exports.p2p = new p2p()
} 
else {
    root.p2p = new p2p()
}