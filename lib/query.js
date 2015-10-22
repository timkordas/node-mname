var protocol = require('./protocol');
var ipaddr = require('ipaddr.js');
var protocol = require('./protocol');
var queryTypes = protocol.queryTypes;
var nsRecord = require('./records/ns');
var soaRecord = require('./records/soa');
var assert = require('assert-plus');


function Query(opts) {
        assert.object(opts, 'options');
        assert.buffer(opts.data, 'options.data');
        assert.string(opts.family, 'options.family');

        var dobj = protocol.decode(opts.data, 'queryMessage');
        var q = dobj.val;
        assert.object(q);

        delete (opts.data);
        this.src = opts;
        this.family = opts.family;

        this.id = q.header.id;
        this.query = q;

        this.reset();
        this.response.header.qdCount = q.header.qdCount;
        this.response.question = q.question;
}

Query.prototype.reset = function () {
        var q = this.query;
        var r = this.response = {};

        r.header = {
                id: q.header.id,
                flags: {},
                qdCount: 0,
                anCount: 0,
                nsCount: 0,
                arCount: 0
        };
        r.answers = [];
        r.authority = [];
        r.additional = [];

        /* Inherit the query's flags until we override them */
        r.header.flags = Object.create(q.header.flags);

        /* Respond with NOTIMP unless we set otherwise */
        r.header.flags.rcode = protocol.DNS_ENOTIMP;
        r.header.flags.qr = true;

        parseEdns.call(this);
}

function parseEdns() {
        var q = this.query;
        var r = this.response;

        if (this.family === 'udp')
                this.maxReplySize = 512;
        else
                this.maxReplySize = 65530;

        if (typeof (q.additional) === 'object') {
                var add = q.additional;
                if (!(add instanceof Array))
                        add = [add];

                var edns = add.filter(function (a) {
                        return (a.rtype === queryTypes['OPT']);
                }).pop();

                if (edns) {
                        var maxReplySize = this.maxReplySize;
                        maxReplySize = edns.rclass;
                        if (maxReplySize > 1200)
                                maxReplySize = 1200;
                        r.additional.push({
                                name: '.',
                                rtype: queryTypes['OPT'],
                                rclass: maxReplySize,
                                rttl: 0,
                                rdata: { options: [] }
                        });
                        r.header.arCount++;
                        if (this.family === 'udp')
                                this.maxReplySize = maxReplySize;
                }
        }
}

Query.prototype.answers = function answers() {
        return this.response.answers.map(function(r) {
                return {
                        name: r.name,
                        type: queryTypes[r.rtype],
                        record: r.rdata,
                        ttl: r.rttl
                };
        });
}

Query.prototype.name = function name() {
        return (this.query.question.name);
}

Query.prototype.type = function type() {
        return (queryTypes[this.query.question.type]);
}

Query.prototype.ixfrBase = function ixfrBase() {
        var q = this.query;
        assert.strictEqual(q.question.type, queryTypes['IXFR']);
        assert.object(q.authority);
        assert.strictEqual(q.authority.rtype, queryTypes['SOA']);
        return (q.authority.rdata.serial);
}

Query.prototype.setError = function setError(name) {
        var code = protocol['DNS_' + name.toUpperCase()];
        if (code === undefined) {
                throw new Error('invalid error code %s', name);
        }
        this.response.header.flags.rcode = code;
}

Query.prototype.operation = function operation() {
        var h = this.query.header;
        switch (h.flags.opcode) {
        case 0:
                return 'query';
        case 2:
                return 'status';
        case 4:
                return 'notify';
        case 5:
                return 'update';
        default:
                throw new Error('invalid operation %d', h.flags.opcode);
        }
};

Query.prototype.encode = function encode(recurse) {
        var encoded = protocol.encode(this.response,
            (this.response.header.qdCount > 0) ? 'answerMessage' : 
            'answerMessageNoQ');

        if (encoded.length > this.maxReplySize) {
                if (recurse || this.family !== 'udp')
                        throw (new Error('Truncated answer message ' +
                            'too large to send: ' + encoded.length + ' bytes'));
                var r = this.response;
                r.header.flags.tc = true;
                r.answers = [];
                r.authority = [];
                r.additional = [];
                return (encode(true));
        }

        return (encoded);
};
Query.prototype.addAuthority = function(name, record, ttl) {
        assert.string(name, 'name');
        assert.object(record, 'record');
        assert.optionalNumber(ttl, 'ttl');

        var authority = {
                name:   name,
                rclass: 1,  // INET
                rttl:   ttl || 5,
                rdata:  record
        };
        if (record instanceof nsRecord)
                authority.rtype = queryTypes['NS'];
        else if (record instanceof soaRecord)
                authority.rtype = queryTypes['SOA'];
        else
                throw (new TypeError('invalid type for authority section record'));

        var r = this.response;
        r.authority.push(authority);
        r.header.nsCount++;
        r.header.flags.aa = true;
};
Query.prototype.addAdditional = function(name, record, ttl) {
        assert.string(name, 'name');
        assert.object(record, 'record');
        assert.optionalNumber(ttl, 'ttl');

        var add = {
                name:   name,
                rtype:  queryTypes[record._type],
                rclass: 1,  // INET
                rttl:   ttl || 5,
                rdata:  record
        };

        var r = this.response;
        r.additional.push(add);
        r.header.arCount++;
};

Query.prototype.addAnswer = function(name, record, ttl) {
        assert.string(name, 'name');
        assert.object(record, 'record');
        assert.optionalNumber(ttl, 'ttl');

        if (!queryTypes.hasOwnProperty(record._type))
                throw (new TypeError('unknown queryType: ' + record._type));

        var r = this.response;
        // return ok, we have an answer
        r.header.flags.rcode = protocol.DNS_ENOERR;
        var answer = {
                name:   name,
                rtype:  queryTypes[record._type],
                rclass: 1,  // INET
                rttl:   ttl || 5,
                rdata:  record
        };

        r.answers.push(answer);
        r.header.anCount++;
};

function parseQuery(opts) {
        return (new Query(opts));
}

module.exports = {
        parse: parseQuery
}
