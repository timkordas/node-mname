var validators = require('../validators');
var assert = require('assert-plus');

function SRV(target, port, opts) {
        assert.string(target, 'target host');
        assert.number(port, 'port');
        assert.optionalObject(opts, 'options');

        if (!opts)
                opts = {};

        var defaults = {
                priority: 0,
                weight: 10,
        };

        Object.keys(defaults).forEach(function (key) {
                if (opts[key] !== undefined)
                        return;
                opts[key] = defaults[key];
        });

        this.target = target;
        this.port = port;
        this.weight = opts.weight;
        this.priority = opts.priority;
        this._type = 'SRV';
}
module.exports = SRV;


SRV.prototype.valid = function SRV() {
        var self = this, model = {};
        model = {
                target: validators.nsText, // XXX
                port: validators.UInt16BE,
                weight: validators.UInt16BE,
                priority: validators.UInt16BE
        };
        return validators.validate(self, model);
};
