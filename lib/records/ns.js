var validators = require('../validators');
var assert = require('assert-plus');

function NS(target) {
        assert.string(target, 'target');

        this.target = target;
        this._type = 'NS';
}
module.exports = NS;


NS.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                target: validators.nsName
        };
        return validators.validate(self, model);
};
