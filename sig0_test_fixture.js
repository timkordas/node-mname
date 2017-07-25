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

        // we're going to sign our response.
        query.sig0Key = SIG0_KEY;

        server.send(query);
});
