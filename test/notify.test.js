/*
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

var dig = require('./dig');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');

var test = helper.test;
var before = helper.before;
var after = helper.after;

var server1;
var server2;

before(function (callback) {
        server1 = named.createServer({
                log: helper.getLog('server1')
        });
        server2 = named.createServer({
                log: helper.getLog('server2')
        });

        server1.on('query', function (query, cb) {
                var op = query.operation();
                if (op === 'notify') {
                        query.setError('noerror');
                        query.send();
                }
                cb();
        });

        server1.listenUdp({ address: '::1', port: 9999 }, function() {
                server2.listenUdp({ address: '::1', port: 9991 }, function () {
                        process.nextTick(callback);
                });
        });
});

test('answer notify: foo.com', function (t) {
        var n = server2.createNotify({
                address: '::1',
                port: 9999,
                zone: 'foo.com'
        });
        n.once('response', function (q) {
                t.strictEqual(q.operation(), 'notify');
                t.strictEqual(q.error(), 'noerror');
                t.strictEqual(q.name(), 'foo.com');
                t.end();
        });
        n.once('error', function (err) {
                t.ifError(err);
                t.end();
        })
        n.send();
});

after(function (cb) {
        server1.close(function () {
                server2.close(cb);
        });
});
