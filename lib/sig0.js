/*
 * Copyright (c) 2017 Joyent, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * SIG(0) Signatures for DNS (see RFC2931) -- public key signatures over
 * DNS requests and responses.
 *
 * Structurally almost identical to TSIG signatures -- but with different
 * backing crypto.
 */

module.exports = {
        signRequest: signRequest,
        signResponse: signResponse,
//        signTcpContinuation: signTcpContinuation,
        verifyRequest: verifyRequest,
        verifyResponse: verifyResponse,
//        verifyTcpContinuation: verifyTcpContinuation
};

var protocol = require('./protocol');
var assert = require('assert-plus');
var crypto = require('crypto');

var ALGOS = {
        'rsa-sha1' : 5,
        'rsa-sha256' : 8,
        'rsa-sha512' : 10,
        'ecdsa-p256-sha256' : 13,
        'ecdsa-p384-sha384' : 14,
        'ed25519' : 15
};

var ALGOREV = {};
Object.keys(ALGOS).forEach(function (k) {
        ALGOREV[ALGOS[k]] = k.toUpperCase();
});

function assertKey(key) {
        assert.string(key.name, 'key.name');
        assert.string(key.algorithm, 'key.algorithm');
        assert.buffer(key.data, 'key.data');
        assert.number(ALGOS[key.algorithm], 'supported algorithm');
}

function verifyRequest(msg, keys) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'sig0SignDataReq'));
}

function verifyResponse(msg, keys, reqMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.object(reqMsg, 'signedRequestMessage');
        assert.object(reqMsg.header, 'signedRequestMessage.header');
        assert.arrayOfObject(reqMsg.additional,
            'signedRequestMessage.additional');
        var sigs = reqMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.SIG0);
        });
        assert.ok(tsigs.length === 1, 'signedRequestMessage SIG0 signature');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'sig0SignDataResp', sigs[0].rdata.mac));
}

/*
function verifyTcpContinuation(msg, keys, lastMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.object(lastMsg, 'signedLastMessage');
        assert.object(lastMsg.header, 'signedLastMessage.header');
        assert.arrayOfObject(lastMsg.additional,
            'signedLastMessage.additional');
        var tsigs = lastMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.TSIG);
        });
        assert.ok(tsigs.length === 1, 'signedLastMessage TSIG signature');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'tsigSignTcp', tsigs[0].rdata.mac));
} */

function signRequest(msg, key) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        return (sign(msg, key, 'sig0SignDataReq'));
}

function signResponse(msg, key, reqMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        assert.object(reqMsg.header, 'signedRequestMessage.header');
        assert.arrayOfObject(reqMsg.additional,
            'signedRequestMessage.additional');
        var sigs = reqMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.SIG0);
        });
        assert.ok(tsigs.length === 1, 'signedRequestMessage SIG0 signature');
        return (sign(msg, key, 'sig0SignDataResp', sigs[0].rdata.mac));
}

/*
function signTcpContinuation(msg, key, lastMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        assert.object(lastMsg.header, 'signedLastMessage.header');
        assert.arrayOfObject(lastMsg.additional,
            'signedLastMessage.additional');
        var tsigs = lastMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.TSIG);
        });
        assert.ok(tsigs.length === 1, 'signedLastMessage TSIG signature');
        return (sign(msg, key, 'tsigSignTcp', tsigs[0].rdata.mac));
}
*/

/* SIG0 verify works slightly different from TSIG verify:
 *
 * https://github.com/openbsd/src/blob/master/usr.sbin/bind/lib/dns/dnssec.c#L738
 * vs
 * https://github.com/openbsd/src/blob/master/usr.sbin/bind/lib/dns/tsig.c#L831
 *
 * Basically, we feed our hash with the bare-SIG0, followed by the query chain with
 * SIG0 removed. TSIG does this sort of the other way around.
 */
function verify(msg, keys, format, sigData) {
        console.log("format: " + format);
        var newMsg = Object.create(msg);
        newMsg.header = Object.create(msg.header);
        newMsg.additional = msg.additional.slice();
        var sig0 = newMsg.additional.pop();
        assert.strictEqual(sig0.rtype, protocol.queryTypes.SIG0);
        newMsg.header.arCount--;

        var kname = sig0.rdata.signername;
        var key = keys[kname];
        console.log("key name: " + kname);
        if (key === undefined)
                throw (new Error('Unknown SIG0 key "' + kname + '"'));
        assertKey(key);

        var algo = sig0.rdata.algorithm;
        assert.strictEqual(algo, ALGOS[key.algorithm], 'matching algorithm');

        console.log(sig0);

        var signature = sig0.rdata.signature; // Save what we're going to verify.
        sig0.rdata.signature = Buffer(0);
        sig0.rdata.message = Buffer(0);

        console.log(sig0.rdata);
        
        var blob = protocol.encode(sig0.rdata, format); // digest SIG0
        assert.buffer(blob);
        
        var verifier = crypto.createVerify(ALGOREV[algo]);        
        verifier.update(blob);
        
        blob = protocol.encode(newMsg, 'message');
        verifier.update(blob);

        var cryptoVerified = verifier.verify(key.data, signature);
        
        // check expiration against issuance/inception and expiration.
        var now = new Date().getTime() / 1000;        
        var validTimeSignature = (now < sig0.rdata.expiration && now > sig0.rdata.inception);

        console.log("crypto verify: " + cryptoVerified);
        console.log("time of signature is valid: " + validTimeSignature);
        
        return cryptoVerified && validTimeSignature;
}

function sign(msg, key, format, sigData) {
        var algo = ALGOS[key.algorithm];

        var sig0 = {};

        sig0.message = protocol.encode(msg, 'message');
        sig0.typecovered = 0;
        sig0.algorithm = algo;
        sig0.labels = 0;
        sig0.originalttl = 0;
        sig0.keytag = key.tag;
        sig0.signername = key.name;
        
        var fudge = 300;
        sig0.expiration = new Date() + fudge;
        sig0.inception = new Date() - fudge;
        sig0.signature = new Buffer(0);

        var blob = protocol.encode(sig0, format);
        assert.buffer(blob);

        var signer = crypto.createSign(algo);
        signer.update(blob);
        var signature_data = signer.sign(key, format)

        var signature = {};
        signature.signername = sig0.signername;
        signature.labels = sig0.labels;
        signature.typecovered = sig0.typecovered;
        signature.originalttl = sig0.originalttl;
        signature.algorithm = sig0.algorithm;
        signature.expiration = sig0.expiration;
        signature.inception = sig0.inception;
        signature.rdata.signature = signature_data;

        msg.header.arCount++;
        msg.additional.push(signature);
}
