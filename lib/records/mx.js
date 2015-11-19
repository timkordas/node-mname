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

function MX(exchange, opts) {
        assert.string(exchange, 'exchange');

        if (!opts)
                opts = {};

        var defaults = {
                priority: 0,
                ttl: 600
        };

        Object.keys(defaults).forEach(function (key) {
                if (opts[key] !== undefined)
                        return;
                opts[key] = defaults[key];
        });

        this.exchange = exchange;
        this.ttl = opts.ttl;
        this.priority = opts.priority;
        this._type = 'MX';
}
module.exports = MX;


MX.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                exchange: validators.nsName,
                ttl: validators.UInt32BE,
                priority: validators.UInt16BE
        };
        return validators.validate(self, model);
};
