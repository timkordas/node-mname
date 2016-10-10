/*
 * Copyright (c) 2016 Joyent, Inc
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
var mod_mname = require('../lib');
var dig = require('./dig');
var mod_crypto = require('crypto');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');

var test = helper.test;
var before = helper.before;
var after = helper.after;

var options = { port: 9999, server: '::1' };

var KEY_MD5 = {
        name: 'md5test',
        algorithm: 'hmac-md5',
        data: mod_crypto.randomBytes(8)
};

var KEY_SHA1 = {
        name: 'shatest',
        algorithm: 'hmac-sha1',
        data: mod_crypto.randomBytes(12)
};

var KEY_SHA1_2 = {
        name: 'shatest2',
        algorithm: 'hmac-sha1',
        data: mod_crypto.randomBytes(12)
};

var KEY_SHA1_3 = {
        name: 'shatest',
        algorithm: 'hmac-sha1',
        data: mod_crypto.randomBytes(12)
};

var KEYS = {
        'shatest': KEY_SHA1,
        'md5test': KEY_MD5
};

before(function (callback) {
        this.server = mod_mname.createServer({
                log: helper.getLog('server')
        });
        var server = this.server;

        this.server.on('query', function (query, cb) {
                if (!query.isSigned() || !query.verify(KEYS)) {
                        query.setError('notauth');
                        query.send();
                        cb();
                        return;
                }
                var domain = query.name();
                var record;
                if (query.type() === 'AXFR') {
                        var soa = new mod_mname.SOARecord(domain);
                        query.addAnswer(domain, soa, 300);
                        query.send();
                        record = new mod_mname.ARecord('127.0.0.1');
                        query.addAnswer(domain, record, 300);
                        query.send();
                        query.addAnswer(domain, soa, 300);
                        query.send();
                        cb();
                } else {
                        record = new mod_mname.ARecord('127.0.0.1');
                        query.addAnswer(domain, record, 300);
                        query.send();
                        cb();
                }
        });

        this.server.listenUdp({port: options.port, address: options.server},
            function () {
                server.listenTcp({port: options.port, address: options.server},
                    function () {
                        process.nextTick(callback);
                });
        });
});

after(function (cb) {
        this.server.close(cb);
});

process.on('uncaughtException', function(err) {
  console.error(err.stack);
});

test('tsig required', function (t) {
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.equal(results.status, 'notauth');
                t.end();
        });
});

test('tsig md5', function (t) {
        options.key = KEY_MD5;
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.equal(results.status, 'noerror');
                t.ok(!results.tsigFail);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 300, type: 'A',
                        target: '127.0.0.1'
                }]);
                t.end();
        });
});

test('tsig sha1', function (t) {
        options.key = KEY_SHA1;
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.equal(results.status, 'noerror');
                t.ok(!results.tsigFail);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 300, type: 'A',
                        target: '127.0.0.1'
                }]);
                t.end();
        });
});

test('tsig sha1 with unknown key', function (t) {
        options.key = KEY_SHA1_2;
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.equal(results.status, 'notauth');
                t.end();
        });
});

test('tsig sha1 with wrong key', function (t) {
        options.key = KEY_SHA1_3;
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.equal(results.status, 'notauth');
                t.end();
        });
});

test('tsig axfr', function (t) {
        options.key = KEY_SHA1;
        dig('example.com', 'AXFR', options, function (err, results) {
                t.ifError(err);
                t.strictEqual(results.status, null);
                t.ok(!results.tsigFail);
                var noTsig = results.answers.filter(function (rec) {
                        return (rec.type !== 'TSIG');
                });
                t.deepEqual(noTsig, [{
                        name: 'example.com.',
                        ttl: 300, type: 'SOA',
                        target: 'example.com. hostmaster.example.com. ' +
                            '0 86400 7200 1209600 10800'
                }, {
                        name: 'example.com.',
                        ttl: 300, type: 'A',
                        target: '127.0.0.1'
                }, {
                        name: 'example.com.',
                        ttl: 300, type: 'SOA',
                        target: 'example.com. hostmaster.example.com. ' +
                            '0 86400 7200 1209600 10800'
                }]);
                t.end();
        });
});
