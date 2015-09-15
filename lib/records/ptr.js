var validators = require('../validators');
var assert = require('assert-plus');

function PTR(target) {
        assert.string(target, 'target');

        this.target = target;
        this._type = 'PTR';
}
module.exports = PTR;


PTR.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                target: validators.nsName
        };
        return validators.validate(self, model);
};
