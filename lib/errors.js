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
/*
 * This excellent error creator concept was borrowed from Mark Cavage
 * https://github.com/mcavage/node-ldapjs/blob/master/lib/errors/index.js
 */


var util = require('util');

var CODES = {
        DNS_NO_ERROR:        0,
        DNS_PROTOCOL_ERROR:  1,
        DNS_CANNOT_PROCESS:  2,
        DNS_NO_NAME:         3,
        DNS_NOT_IMPLEMENTED: 4,
        DNS_REFUSED:         5,
        DNS_EXCEPTION:       6
};

var ERRORS = [];

function DnsError(name, code, msg, caller) {
        if (Error.captureStackTrace)
                Error.captureStackTrace(this, caller || DnsError);

        this.code = code;
        this.name = name;
        this.message = msg || name;
}

util.inherits(DnsError, Error);


module.exports = {};
module.exports.DnsError = DnsError;

Object.keys(CODES).forEach(function (code) {
        module.exports[code] = CODES[code];

        if (CODES[code] === 0)
                return;

        var err = '', msg = '';
        var pieces = code.split('_').slice(1);
        for (var i in pieces) {
                var lc = pieces[i].toLowerCase();
                var key = lc.charAt(0).toUpperCase() + lc.slice(1);
                err += key;
                msg += key + ((i + 1) < pieces.length ? ' ' : '');
        }

        if (!/\w+Error$/.test(err))
                err += 'Error';

        module.exports[err] = function (message, caller) {
                DnsError.call(this,
                    err,
                    CODES[code],
                    message || msg,
                    caller || module.exports[err]);
        };
        module.exports[err].constructor = module.exports[err];
        util.inherits(module.exports[err], DnsError);

        ERRORS[CODES[code]] = {
                err: err,
                message: msg
        };
});
