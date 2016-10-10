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

// Quick and dirty 'dig' wrapper

var assert = require('assert');
var spawn = require('child_process').spawn;
var sprintf = require('util').format;
var path = require('path');


///--- Globals

var DIG = 'dig';



///--- Helpers

function parseAnswer(tokens) {
        var t = tokens.filter(function (v) {
                return (v !== '' ? v : undefined);
        });

        var r = {
                name:   t[0],
                ttl:    parseInt(t[1], 10),
                type:   t[3],
                target: t[4]
        };

        return (r);
}


function parseDig(output) {
        var lines = output.split(/\n/);
        var section = 'header';

        var results = {
                id: null,
                status: null,
                question: null,
                tsigFail: false,
                answers: [],
                additional: [],
                authority: []
        };

        lines.forEach(function (l) {
                if (l === '') {
                        section = undefined;
                } else if (/^;; QUESTION SECTION:/.test(l)) {
                        section = 'question';
                } else if (/^;; ANSWER SECTION:/.test(l)) {
                        section = 'answer';
                } else if (/^;; ADDITIONAL SECTION:/.test(l)) {
                        section = 'additional';
                } else if (/^;; AUTHORITY SECTION:/.test(l)) {
                        section = 'authority';
                } else if (/^; <<>> DiG.* axfr /i.test(l)) {
                        section = 'answer';
                }

                if (section === 'question') {
                        if (/^;([A-Za-z0-9])*\./.test(l)) {
                                results.question =
                                        l.match(/([A-Za-z0-9_\-\.])+/)[0];
                        }
                }

                if (section === 'answer') {
                        if (/^([_A-Za-z0-9])+/.test(l)) {
                                var tokens = l.match(/(.*)/)[0].split(/\t/);
                                var answer = parseAnswer(tokens);
                                if (answer)
                                        results.answers.push(answer);
                        }
                }

                if (/^;; ->>HEADER<<-/.test(l)) {
                        var m = l.match(/status: ([A-Z]+)/)
                        results.status = m[1].toLowerCase();
                        m = l.match(/id: ([0-9]+)/);
                        results.id = parseInt(m[1], 10);
                }

                if (/Some TSIG could not be validated/.test(l) ||
                    /tsig verify failure/.test(l)) {
                        results.tsigFail = true;
                }

                if (/^; Transfer failed/.test(l)) {
                        results.status = 'failed';
                }
        });

        return (results);
}



///--- API

function dig(name, type, options, callback) {
        if (typeof (name) !== 'string')
                throw new TypeError('name (string) is required');
        if (typeof (type) !== 'string')
                throw new TypeError('type (string) is required');
        if (typeof (options) === 'function') {
                callback = options;
                options = {};
        }

        type = type.toUpperCase();

        var opts = [];
        if (options.server) {
                opts.push('@' + options.server);
        }
        if (options.port) {
                opts.push('-p');
                opts.push(options.port);
        }
        if (options.key) {
                opts.push('-y');
                var key = options.key;
                opts.push(key.algorithm + ':' + key.name + ':' +
                    key.data.toString('base64'));
        }
        opts = opts.concat(['-t', type, name, '+time=1', '+retry=0']);

        var kid = spawn('dig', opts, {
                stdio: ['pipe', 'pipe', 'inherit'],
        });
        kid.stdin.end();
        var stdout = [];
        kid.stdout.on('readable', function () {
                var b;
                while ((b = kid.stdout.read()) !== null) {
                        stdout.push(b);
                }
        });
        kid.on('exit', function (exitStatus) {
                if (exitStatus !== 0) {
                        return (callback(
                            new Error('dig exited with status ' + exitStatus)));
                }
                return (callback(null, parseDig(
                    Buffer.concat(stdout).toString('ascii'))));
        });
}



///--- Exports

module.exports = dig;
