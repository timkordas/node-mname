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
var validators = require('../validators');
var assert = require('assert-plus');

function SOA(host, opts) {
        assert.string(host, 'host');
        assert.optionalObject(opts, 'options');

        if (!opts)
                opts = {};

        var defaults = {
                admin: 'hostmaster.' + host,
                serial: 0,
                refresh: 86400,
                retry: 7200,
                expire: 1209600,
                ttl: 10800
        };

        Object.keys(defaults).forEach(function (key) {
                if (opts[key] !== undefined)
                        return;
                opts[key] = defaults[key];
        });

        this.host = host;
        this.admin = opts.admin;
        this.serial = opts.serial;
        this.refresh = opts.refresh;
        this.retry = opts.retry;
        this.expire = opts.expire;
        this.ttl = opts.ttl;
        this._type = 'SOA';
}
module.exports = SOA;


SOA.prototype.valid = function () {
        var self = this, model = {};

        model = {
                host: validators.nsName,
                admin: validators.nsName,
                serial: validators.UInt32BE,
                refresh: validators.UInt32BE,
                retry: validators.UInt32BE,
                expire: validators.UInt32BE,
                ttl: validators.UInt32BE
        };

        return validators.validate(self, model);
};
