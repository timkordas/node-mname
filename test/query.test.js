/*
 * Copyright (c) 2015 Trevor Orsztynowicz
 * Copyright (c) 2015 Joyent, Inc
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
