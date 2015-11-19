var validators = require('../validators');
var assert = require('assert-plus');

function A(target) {
        assert.string(target, 'target IPv4Addr');

        this.target = target;
        this._type = 'A';
}
module.exports = A;


A.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                target: validators.IPv4
        };
        return validators.validate(self, model);
};
