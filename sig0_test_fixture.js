var port = 9999;
var host = '127.0.0.1';

var named = require("./lib");
var Query = require('./lib/query');
var protocol = require('./lib/protocol');
var mod_sig0 = require("./lib/sig0");

var server = named.createServer();
server.listen(port, host, function() {
  console.log('DNS server started on port 9999');
});
console.log(named.SoaRecord);

var TSIG_KEY = {
        name: 'tsig_tjktest',
        algorithm: 'hmac-sha1',
        data: Buffer.from("ZkoZIUlo3wc0UkL5l7lrf9ppS7M=", "base64")
};

var SIG0_KEY = {
        name: 'tjktest',
        tag: 19115,
        algorithm: 'rsa-sha1',
        pubkey: Buffer.from(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjzWEj72KHR/4DVifXIApOv1vz\n" +
                        "eU8gdXBR4RXZaR5jTkFTLmYYas5DhX5L5SPYWCgpoy+ou67ML0u3Pd95wrUZqXrs\n" +
                        "WG79FVAgeav/ehEO5srECZtFtQWYq9odgmimIBBYEF0Yyw8+8q4hDt6v1E9KMIUG\n" +
                        "b1t2MKRvgGSZQbl0+wIDAQAB\n" +
                        "-----END PUBLIC KEY-----"),
        prikey: Buffer.from(
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIICXAIBAAKBgQCjzWEj72KHR/4DVifXIApOv1vzeU8gdXBR4RXZaR5jTkFTLmYY\n" +
                        "as5DhX5L5SPYWCgpoy+ou67ML0u3Pd95wrUZqXrsWG79FVAgeav/ehEO5srECZtF\n" +
                        "tQWYq9odgmimIBBYEF0Yyw8+8q4hDt6v1E9KMIUGb1t2MKRvgGSZQbl0+wIDAQAB\n" +
                        "AoGALVD9heaNWKXXJW8peH+Zum2Ab9xowq8a0tw1oj9Ns+WLdwrIHgs2Y0HEThTn\n" +
                        "lMvW2KYX4lOCKWUQSnKop9PxK+XxkQT062zd2Rl+adewgGx8s5WOUVeupgT7Sj7o\n" +
                        "mlpYFtJoy/aeewqEGHBgEMswjpSkh59FzZbWMgJAJPQy6/ECQQD0BzKw/2p6jW8A\n" +
                        "QU7vmqg8oyYuZKy2etBOiUvw0wW6KCBV1EB/W4EAdFwy5uRmC0GUjphzZZLX682a\n" +
                        "pVd23BwnAkEA0Nf2u0go3pqkJRVN3Y7NVfunps/PGvAr5r0Lz2YhO0nW84RlQvRV\n" +
                        "7Eeb0AVikBAEjTNeAtzS6yXt3/DsBS0I2wJAJF0mOqX1EgodbmZNAvuC8nZFbEho\n" +
                        "TFEE1Y80F9D6W4E7QE7+xXu3P4AXdSZfBq3Kuf59zURnm3FyFAdrfzTRpQJASZ8I\n" +
                        "RIcwmSCMouH6vBL+QcRgGocBbG6kG0gjZK6NInhqRRg0FkFKFOw9ejybvUtYP2qP\n" +
                        "RpUP6YNKcvpcSYrRpwJBAMZ/JGdLADHHU2RGivm9D2eeDqejnpG47jkMimCN92WS\n" +
                        "V4oLOe7/DoveFUAJRfRd/QRP0OTo+9gJIRNhxxx1uM0=\n" +
                        "-----END RSA PRIVATE KEY-----\n")

};

var KEYS = {
        "tsig_tjktest" : TSIG_KEY,
        "tjktest" : SIG0_KEY
};
server.on('query', function(query) {
        console.log("S: got query");
        if (query.isSigned()) {
                console.log("signed");
        } else {
                console.log("NOT signed");
        }
        if (query.isSigned() && query.verify(KEYS)) {
                console.log("verifies!");
        } else {
                console.log("failing verify!");
        }
        // return a dummy response.
        var domain = query.name();
        var record = new named.SOARecord(domain, {serial: 12345, ttl: 300});
        query.addAnswer(domain, record, 300);
        query.sig0Key = SIG0_KEY;

/*
        // self verify ?
        console.log("attempting self-verify");
        wireResp = query.encode();
//        console.log(wireResp);

        var qopts = {
                family: 'udp',
                address: '1.23.4.5',
                port: 89,
                data: wireResp
        };

        var reply = Query.parse(qopts);
        console.log("response: ", reply.query);
        console.log("req: ", query.query);
        console.log("trying to verify: ", mod_sig0.verifyResponse(reply.query, KEYS, query.query));
*/
        server.send(query);
});

var dgram = require('dgram');
var client = dgram.createSocket('udp4');

function simpleDnsQuery(name, type, qclass) {
        var req = {};
        req.header = {};
        req.header.id = 1234;
        req.header.flags = {
                qr:     false,
                opcode: 0,
                aa:     false,
                tc:     false,
                rd:     false,
                ra:     false,
                z:      false,
                ad:     false,
                cd:     false,
                rcode:  0
        };
        req.header.qdCount = 1;
        req.header.anCount = 0;
        req.header.nsCount = 0;
        req.header.arCount = 0;
        req.question = [];
        req.answer = [];
        req.authority = [];
        req.additional = [];

        var question = {};
        question.name = name;
        question.type = protocol.queryTypes.A;
        question.qclass = protocol.qClasses.ANY;
        req.question.push(question);

        return (req);
}

// Generate a signed request

var r = simpleDnsQuery('example.com', protocol.queryTypes.A, protocol.qClasses.ANY);
mod_sig0.signRequest(r, SIG0_KEY);
var dnsReq = protocol.encode(r, 'message');

var qopts = {
        family: 'udp',
        address: '1.2.3.4',
        port: 88,
        data: dnsReq
};
var parsed = Query.parse(qopts);
console.log("directly signed ?", parsed.isSigned());
console.log("directly verifies ?", parsed.verify(KEYS));

client.on('message', function (message, remote) {
        console.log("Got a message");

        var qopts = {
                family: 'udp',
                address: remote.address,
                port: remote.port,
                data: message
        };

        var reply = Query.parse(qopts);
        qopts.data = dnsReq;
        qopts = {
                family: 'udp',
                address: '1.2.3.4',
                port: 88,
                data: dnsReq
        };
        var origReq = Query.parse(qopts);
        console.log("reply qr: ", reply.testFlag('qr'));
        if (reply.isSigned()) {
                console.log("Signed Reply");
                console.log("response: ", reply.query);
                console.log("req: ", r);
                // THIS WORKS with parsed.query; BUT NOT with origReq.query. WTF
                console.log("reply before verify: ", reply);
                console.log("parsed verify?", mod_sig0.verifyResponse(reply.query, KEYS, parsed.query));
                console.log("parsed verify?", mod_sig0.verifyResponse(reply.query, KEYS, parsed.query));
                console.log("origReq verify?", mod_sig0.verifyResponse(reply.query, KEYS, origReq.query));
                console.log("query.js verify?", reply.verify(KEYS, parsed.query));
        }
});

function sendMessage(c, m) {
        c.send(m, 0, m.length, port, host,
                    function(err, bytes) {
                            if (err) throw err;
                            console.log('C: sent message sent to ' + host +':'+ port);
                    });
}

server.on('listening', function () { sendMessage(client, dnsReq)});
