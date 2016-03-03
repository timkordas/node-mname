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
var protocol = require('../lib/protocol');

var dig = require('./dig');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');
var net = require('net');

var test = helper.test;
var before = helper.before;
var after = helper.after;

var server1;

before(function (callback) {
        server1 = named.createServer({
                log: helper.getLog('server1')
        });

        server1.on('query', function (query, cb) {
                var domain = query.name();
                var type = query.type();

                if (type === 'A') {
                        var rec = new named.ARecord('127.0.0.1');
                        query.addAnswer(domain, rec);
                        query.send();
                        cb();
                } else if (type === 'AAAA') {
                        setTimeout(function () {
                                var rec = new named.AAAARecord('::1');
                                query.addAnswer(domain, rec);
                                query.send();
                                cb();
                        }, 50);
                } else {
                        cb();
                }
        });

        server1.listenUdp({ address: '::1', port: 9999 });
        server1.listenTcp({ address: '::1', port: 9999 }, function() {
                process.nextTick(callback);
        });
});

test('simple pipelining test', function (t) {
        var q1 = {};
        q1.header = {
                id: 1234,
                flags: {
                        opcode: protocol.opCodes.QUERY,
                        rcode: protocol.rCodes.NOERROR
                },
                qdCount: 1,
                anCount: 0,
                nsCount: 0,
                arCount: 0
        };
        q1.question = [{
                name: 'foo.bar',
                type: protocol.queryTypes.A,
                qclass: protocol.qClasses.IN
        }];
        q1.answer = [];
        q1.authority = [];
        q1.additional = [];
        var q1Buf = lengthPrefix(protocol.encode(q1, 'message'));

        var q2 = q1;
        q2.header.id = 1235;
        q2.question = [{
                name: 'baz.bar',
                type: protocol.queryTypes.AAAA,
                qclass: protocol.qClasses.IN
        }];
        var q2Buf = lengthPrefix(protocol.encode(q2, 'message'));

        var q3 = q1;
        q3.header.id = 1236;
        q3.question[0].type = protocol.queryTypes.A;
        var q3Buf = lengthPrefix(protocol.encode(q3, 'message'));

        var sock = net.connect(9999, '::1');

        var outstanding = {};
        var replies = {};
        var order = [];

        sock.on('connect', function () {
                sock.write(q1Buf);
                outstanding[1234] = true;
                sock.write(q2Buf);
                outstanding[1235] = true;
                sock.write(q3Buf);
                outstanding[1236] = true;
        });

        var buf = new Buffer(0);
        sock.on('readable', function () {
                var b;
                while ((b = sock.read()) !== null)
                        buf = Buffer.concat([buf, b]);
                while (buf.length > 2) {
                        var len = buf.readUInt16BE(0);
                        if (buf.length >= len + 2) {
                                var pkt = buf.slice(2, len + 2);
                                buf = buf.slice(len + 2);
                                var msg = protocol.decode(pkt, 'message');
                                onMessage(msg);
                        } else {
                                break;
                        }
                }
        });

        function onMessage(msg) {
                t.ok(outstanding[msg.header.id]);
                delete outstanding[msg.header.id];
                replies[msg.header.id] = msg;
                order.push(msg.header.id);
                if (Object.keys(outstanding).length < 1) {
                        sock.end();
                        onComplete();
                }
        }

        function onComplete() {
                t.deepEqual(order, [1234, 1236, 1235]);
                t.strictEqual(replies[1234].answer[0].name, 'foo.bar');
                t.strictEqual(replies[1235].answer[0].name, 'baz.bar');
                t.strictEqual(replies[1236].answer[0].name, 'baz.bar');
                t.strictEqual(replies[1236].answer[0].rtype,
                    protocol.queryTypes.A);
                t.done();
        }
});

function lengthPrefix(buf) {
        var buf2 = new Buffer(buf.length + 2);
        buf.copy(buf2, 2);
        buf2.writeUInt16BE(buf.length, 0);
        return (buf2);
}

after(function (cb) {
        server1.close(cb);
});
