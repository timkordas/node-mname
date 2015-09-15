var validators = require('../validators');
var assert = require('assert-plus');

function AAAA(target) {
        assert.string(target, 'target IPv6Addr');

        this.target = target;
        this._type = 'AAAA';
}
module.exports = AAAA;

AAAA.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                target: validators.IPv6
        };
        return validators.validate(self, model);
};
