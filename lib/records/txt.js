var validators = require('../validators');
var assert = require('assert-plus');

function TXT(target) {
        assert.string(target, 'target');

        this.target = target;
        this._type = 'TXT';
}
module.exports = TXT;


TXT.prototype.valid = function () {
        var self = this, model = {};
        model = {
                target: validators.nsText
        };
        return validators.validate(self, model);
};
