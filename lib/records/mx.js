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
