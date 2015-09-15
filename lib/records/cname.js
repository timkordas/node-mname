var validators = require('../validators');
var assert = require('assert-plus');

function CNAME(target) {
        assert.string(target, 'target');

        this.target = target;
        this._type = 'CNAME';
}
module.exports = CNAME;


CNAME.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                target: validators.nsName
        };
        return validators.validate(self, model);
};
