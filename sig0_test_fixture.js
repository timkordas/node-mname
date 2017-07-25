named = require("./lib");
var server = named.createServer();
server.listen(9999, '127.0.0.1', function() {
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
        algorithm: 'rsa-sha1',
        data: Buffer.from(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjzWEj72KHR/4DVifXIApOv1vz\n" +
                        "eU8gdXBR4RXZaR5jTkFTLmYYas5DhX5L5SPYWCgpoy+ou67ML0u3Pd95wrUZqXrs\n" +
                        "WG79FVAgeav/ehEO5srECZtFtQWYq9odgmimIBBYEF0Yyw8+8q4hDt6v1E9KMIUG\n" +
                        "b1t2MKRvgGSZQbl0+wIDAQAB\n" +
                        "-----END PUBLIC KEY-----")
};

var KEYS = {
        "tsig_tjktest" : TSIG_KEY,
        "tjktest" : SIG0_KEY
};
server.on('query', function(query) {
        console.log(query);
        if (query.isSigned()) {
                console.log("signed\n");
        }
        if (query.isSigned() && query.verify(KEYS)) {
                console.log("verifies!\n");
        }
        // return a dummy response.
        var domain = query.name();
        var record = new named.SOARecord(domain, {serial: 12345, ttl: 300});
        query.addAnswer(domain, record, 300);
        server.send(query);
});
