var named = require('../lib');
var dnsBuffer = require('./dnsbuffer');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js'];
var helper = require('./helper');

var test = helper.test;
var before = helper.before;
var after = helper.after;

var qopts = {};

before(function(callback) {
        try {
                qopts.data = dnsBuffer.samples[0].raw,
                qopts.family = 'udp';
                qopts.address = '127.0.0.1';
                qopts.port = 23456;

                process.nextTick(callback);
        }
        catch (e) {
                console.error(e.stack);
                process.exit(1);
        }
});


test('decode a query datagram', function(t) {
        var query = named.Query.parse(qopts);
        t.end();
});

test('encode an null-response query object', function(t) {
        var query = named.Query.parse(qopts);
        query.setError('enoerr');
        var buf = query.encode();
        var ok = dnsBuffer.samples[0].raw;
        t.deepEqual(buf, ok);
        t.end();
});

// TODO test adding a record
// TODO test name response
// TODO test answers response
