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
/*
 *  # Protocol
 *
 *  Stores protocol definitions and their primitives as well as any other
 *  associated protocol constants
 *
 *  ## References
 *
 *  http://tools.ietf.org/html/rfc1035
 *  http://tools.ietf.org/html/rfc4408
 *  http://tools.ietf.org/html/rfc2782
 *  http://tools.ietf.org/html/rfc3596
 *
 *  ## Notes
 *
 *  - Even though RFC1035 says that questions should support multiple queries
 *    the reality is *nobody* does this. MS DNS doesn't support it and
 *    apparently BIND doesn't support it as well. That implies no client side
 *    tools do either - so we will not worry about that complication.
 *
 *  - DNS Extensions have been proposed, but another case of chicken-and-egg.
 *    These extensions make it _possible_ to have DNS queries over 512 bytes in
 *    length, but because it is not universally supported, nobody does it.
 */


var ipaddr = require('ipaddr.js');
var assert = require('assert-plus');
var DNSBuffer = require('./dns-buffer');

var QCLASS_IN   = 0x01; // the internet
var QCLASS_CS   = 0x02; // obsolete
var QCLASS_CH   = 0x03; // chaos class. yes this actually exists
var QCLASS_HS   = 0x04; // Hesiod
var DNS_ENOERR  = 0x00; // No error
var DNS_EFORMAT = 0x01; // Formatting Error
var DNS_ESERVER = 0x02; // server it unable to process
var DNS_ENONAME = 0x03; // name does not exist
var DNS_ENOTIMP = 0x04; // feature not implemented on this server
var DNS_EREFUSE = 0x05; // refused for policy reasons

var Formats = {};

Formats.answer = {
        name: { type: '_nsName' },
        rtype: { type: 'UInt16BE' },
        rclass: { type: 'UInt16BE' },
        rttl: { type: 'UInt32BE' },
        rdata: { type: '_nsData' }     // rdlength is prepended to this field
};

Formats.question = {
        name: { type: '_nsName' },
        type: { type: 'UInt16BE' },
        qclass: { type: 'UInt16BE' }
};

Formats.header = {
        id: { type: 'UInt16BE' },
        flags: { type: '_nsFlags' },
        qdCount: { type: 'UInt16BE' },
        anCount: { type: 'UInt16BE' },
        nsCount: { type: 'UInt16BE' },
        arCount: { type: 'UInt16BE' }
};

Formats.soa = {
        host: { type: '_nsName' },
        admin: { type: '_nsName' },
        serial: { type: 'UInt32BE' },
        refresh: { type: 'UInt32BE' },
        retry: { type: 'UInt32BE' },
        expire: { type: 'UInt32BE' },
        ttl: { type: 'UInt32BE' }
};

Formats.mx = {
        priority: { type: 'UInt16BE' },
        exchange: { type: '_nsName' }
};

Formats.txt = {
        text: { type: '_nsText' }
};

Formats.opt = {
        options: { type: '_ednsOptions' }
};

Formats.srv = {
        priority: { type: 'UInt16BE' },
        weight: { type: 'UInt16BE' },
        port: { type: 'UInt16BE' },
        target: { type: '_nsName' }
};

Formats.queryMessage = {
        header: { type: { format: 'header' } },
        question: { type: { format: 'question' },
            count: ['header', 'qdCount'] },
        authority: { type: '_nsAuthority',
            count: ['header', 'nsCount'] },
        additional: { type: '_nsAdditional',
            count: ['header', 'arCount'] }
};

Formats.answerMessage = {
        header: { type: { format: 'header' } },
        question: { type: { format: 'question' } },
        answers: { type: '_nsAnswers' },
        authority: { type: '_nsAuthority' },
        additional: { type: '_nsAdditional' }
};

Formats.answerMessageNoQ = {
        header: { type: { format: 'header' } },
        answers: { type: '_nsAnswers' },
        authority: { type: '_nsAuthority' },
        additional: { type: '_nsAdditional' }
};

// turns a dotted-decimal address into a UInt32
function parseIPv4(addr) {
        assert.string(addr);

        var octets = addr.split('.').map(function (octet) {
                return (parseInt(octet, 10));
        });
        if (octets.length !== 4)
                throw new TypeError('valid IP address required');
        var b = new Buffer(octets);
        return (b.readUInt32BE(0));
}


function parseIPv6(addr) {
        assert.string(addr);

        var a;
        try {
                a = ipaddr.parse(addr);
        } catch (e) {
                return false;
        }

        return a.parts;

}


// each of these serializers are functions which accept a value to serialize
// and must returns the serialized value as a buffer
var serializers = {
        'UInt32BE': {
                encoder: function (buf, v, ctx) {
                        assert.number(v, ctx.field);
                        buf.writeUInt32(v);
                },
                decoder: function (buf, ctx) {
                        return (buf.readUInt32());
                }
        },
        'UInt16BE': {
                encoder: function (buf, v, ctx) {
                        assert.number(v, ctx.field);
                        buf.writeUInt16(v);
                },
                decoder: function (buf, ctx) {
                        return (buf.readUInt16());
                }
        },
        '_nsAnswers': {
                encoder: function (buf, v, ctx) {
                        assert.arrayOfObject(v, 'answers');
                        for (var i = 0; i < v.length; ++i)
                                _encode(buf, v[i], 'answer', ctx);
                }
        },
        '_nsAuthority': {
                encoder: function (buf, v, ctx) {
                        if (v === undefined)
                                return;
                        assert.arrayOfObject(v, 'authority');
                        for (var i = 0; i < v.length; ++i)
                                _encode(buf, v[i], 'answer', ctx);
                },
                decoder: function (buf, ctx) {
                        return (_decode(buf, 'answer', ctx));
                }
        },
        '_nsAdditional': {
                encoder: function (buf, v, ctx) {
                        if (v === undefined)
                                return;
                        assert.arrayOfObject(v, 'additional');
                        for (var i = 0; i < v.length; ++i)
                                _encode(buf, v[i], 'answer', ctx);
                },
                decoder: function (buf, ctx) {
                        return (_decode(buf, 'answer', ctx));
                }
        },
        '_nsFlags': {
                encoder: function (buf, v, ctx) {
                        assert.object(v, 'flags');
                        var f = 0x0000;
                        f = f | (v.qr << 15);
                        f = f | (v.opcode << 11);
                        f = f | (v.aa << 10);
                        f = f | (v.tc << 9);
                        f = f | (v.rd << 8);
                        f = f | (v.ra << 7);
                        f = f | (v.z  << 6);
                        f = f | (v.ad << 5);
                        f = f | (v.cd << 4);
                        f = f | v.rcode;
                        buf.writeUInt16(f);
                },
                decoder: function (buf, ctx) {
                        var flags = buf.readUInt16();
                        var f = {
                                qr:     ((flags & 0x8000)) ? true : false,
                                opcode: ((flags & 0x7800)),
                                aa:     ((flags & 0x0400)) ? true : false,
                                tc:     ((flags & 0x0200)) ? true : false,
                                rd:     ((flags & 0x0100)) ? true : false,
                                ra:     ((flags & 0x0080)) ? true : false,
                                z:      ((flags & 0x0040)) ? true : false,
                                ad:     ((flags & 0x0020)) ? true : false,
                                cd:     ((flags & 0x0010)) ? true : false,
                                rcode:  ((flags & 0x000F))
                        };
                        return (f);
                }
        },
        '_nsIP4': {
                encoder: function (buf, v, ctx) {
                        assert.string(v, 'ipv4');
                        var a = parseIPv4(v);
                        buf.writeUInt32(a);
                }
        },
        '_nsIP6': {
                encoder: function (buf, v, ctx) {
                        assert.string(v, 'ipv6');
                        var a = parseIPv6(v);
                        for (var i = 0; i < 8; i++) {
                                buf.writeUInt16(a[i]);
                        }
                }
        },
        '_ednsOptions': {
                encoder: function (buf, v, ctx) {
                        assert.arrayOfObject(v, 'edns options');
                        v.forEach(function (opt) {
                                assert.number(opt.code);
                                assert.buffer(opt.data);
                                buf.writeUInt16(opt.code);
                                buf.writeLengthPrefixed(2, function (cbuf) {
                                        cbuf.write(opt.data);
                                });
                        });
                },
                decoder: function (buf, ctx) {
                        var opts = [];
                        while (!buf.atEnd()) {
                                var opt = {};
                                opt.code = buf.readUInt16();
                                buf.readLengthPrefixed(2, function (cbuf) {
                                        opt.data = cbuf.toBuffer();
                                });
                                opts.push(opt);
                        }

                        return (opts);
                }
        },
        '_nsName': {
                encoder: function (buf, v, ctx) {
                        assert.string(v, 'name');
                        buf.writeName(v);
                },
                decoder: function decodeName(buf, ctx) {
                        return (buf.readName());
                }
        },
        '_nsText': {
                encoder: function (buf, v, ctx) {
                        assert.string(v);
                        buf.writeUInt8(v.length);
                        buf.write(new Buffer(v, 'binary'));
                }
        },
        '_nsData': {
                encoder: function (buf, v, ctx) {
                        buf.writeLengthPrefixed(2, function (cbuf) {
                                switch (ctx.parent.rtype) {
                                case queryTypes['A']:
                                        serializers['_nsIP4'].
                                            encoder(cbuf, v.target, ctx);
                                        break;
                                case queryTypes['CNAME']:
                                        serializers['_nsName'].
                                            encoder(cbuf, v.target, ctx);
                                        break;
                                case queryTypes['NS']:
                                        serializers['_nsName'].
                                            encoder(cbuf, v.target, ctx);
                                        break;
                                case queryTypes['SOA']:
                                        _encode(cbuf, v, 'soa', ctx);
                                        break;
                                case queryTypes['MX']:
                                        _encode(cbuf, v, 'mx', ctx);
                                        break;
                                case queryTypes['TXT']:
                                        serializers['_nsText'].
                                            encoder(cbuf, v.target, ctx);
                                        break;
                                case queryTypes['PTR']:
                                        serializers['_nsName'].
                                            encoder(cbuf, v.target, ctx);
                                        break;
                                case queryTypes['AAAA']:
                                        serializers['_nsIP6'].
                                            encoder(cbuf, v.target, ctx);
                                        break;
                                case queryTypes['SRV']:
                                        _encode(cbuf, v, 'srv', ctx);
                                        break;
                                case queryTypes['OPT']:
                                        _encode(cbuf, v, 'opt', ctx);
                                        break;
                                default:
                                        throw new Error('unrecognized nsdata' +
                                            ' type');
                                }
                        });
                },
                decoder: function (buf, ctx) {
                        var res = buf.readLengthPrefixed(2, function (cbuf) {
                                var r;
                                switch (ctx.parent.rtype) {
                                case queryTypes['SOA']:
                                        r = _decode(cbuf, 'soa', ctx);
                                        break;
                                case queryTypes['OPT']:
                                        r = _decode(cbuf, 'opt', ctx);
                                        break;
                                default:
                                        throw (new Error('unsupported nsdata ' +
                                            'type: ' +
                                            queryTypes[ctx.parent.rtype]));
                                }
                                return (r);
                        });
                        return (res);
                }
        }
};

function _encode(buf, obj, format, ctx) {
        assert.object(obj);
        assert.string(format);
        assert.optionalObject(ctx);

        var kidctx = { parent: obj, parentCtx: ctx };

        var fmt = Formats[format];

        var keys = Object.keys(fmt);
        for (var j = 0; j < keys.length; ++j) {
                var f = keys[j];
                kidctx.field = f;
                var type = fmt[f].type;

                if (typeof (type) === 'string') {
                        serializers[type].encoder(buf, obj[f], kidctx);

                } else if (typeof (type) === 'object') {
                        var reftype = type.format;
                        _encode(buf, obj[f], reftype, kidctx);

                } else {
                        var err = new TypeError('Invalid format type');
                        err.type = type;
                        err.context = kidctx;
                        throw (err);
                }
        }

        return (buf.toBuffer());
}

function encode(obj, format) {
        var buf = new DNSBuffer({});
        return (_encode(buf, obj, format));
}

function evalCount(obj, fmtf) {
        var countExpr = fmtf.count || 1;
        var x = obj;
        if (Array.isArray(countExpr)) {
                countExpr.forEach(function (prop) {
                        x = x[prop];
                });
        } else {
                x = countExpr;
        }
        assert.number(x);
        return (x);
}

function _decode(buf, format, ctx) {
        assert.object(buf);
        assert.ok(buf instanceof DNSBuffer);
        assert.string(format);
        assert.optionalObject(ctx);

        var result = {};
        var kidctx = { parent: result, parentCtx: ctx };

        var fmt = Formats[format];
        assert.object(fmt);

        var keys = Object.keys(fmt);
        for (var j = 0; j < keys.length; ++j) {
                var f = keys[j];
                kidctx.field = f;

                var res;
                var type = fmt[f].type;
                var x = evalCount(result, fmt[f]);
                if (x > 1)
                        result[f] = [];

                /*
                 * If the type is a string it's a reference to a serializer.
                 * If the type is an object it's a nested format and we call
                 * decode again with the appropriate offset.
                 */

                for (var i = 0; i < x; ++i) {
                        if (typeof (type) === 'string') {
                                res = serializers[type].decoder(buf, kidctx);

                        } else if (typeof (type) === 'object') {
                                var reftype = type.format;
                                res = _decode(buf, reftype, kidctx);

                        } else {
                                var err = new TypeError('Invalid format type');
                                err.type = type;
                                err.context = kidctx;
                                throw (err);
                        }

                        if (x > 1)
                                result[f].push(res);
                        else
                                result[f] = res;
                }
        }

        return (result);
}

function decode(raw, format) {
        var buf = new DNSBuffer({buffer: raw});
        return (_decode(buf, format));
}

var opCodes = {
        QUERY  : 0,
        IQUERY : 1,
        STATUS : 2,
        NOTIFY : 3,
        UPDATE : 4,
        0      : 'QUERY',
        1      : 'IQUERY',
        2      : 'STATUS',
        3      : 'NOTIFY',
        4      : 'UPDATE'
};

var queryTypes = {
        A     : 0x01,    // ipv4 address
        NS    : 0x02,    // nameserver
        MD    : 0x03,    // obsolete
        MF    : 0x04,    // obsolete
        CNAME : 0x05,    // alias
        SOA   : 0x06,    // start of authority
        MB    : 0x07,    // experimental
        MG    : 0x08,    // experimental
        MR    : 0x09,    // experimental
        NULL  : 0x0A,    // experimental null RR
        WKS   : 0x0B,    // service description
        PTR   : 0x0C,    // reverse entry (inaddr.arpa)
        HINFO : 0x0D,    // host information
        MINFO : 0x0E,    // mailbox or mail list information
        MX    : 0x0F,    // mail exchange
        TXT   : 0x10,    // text strings
        AAAA  : 0x1C,    // ipv6 address
        SRV   : 0x21,    // srv records
        OPT   : 0x29,
        TKEY  : 0xF9,
        TSIG  : 0xFA,
        IXFR  : 0xFB,    // request for incremental transfer
        AXFR  : 0xFC,    // request to transfer entire zone
        MAILA : 0xFE,    // request for mailbox related records
        MAILB : 0xFD,    // request for mail agent RRs
        ANY   : 0xFF,    // any class
        0x01  : 'A',     // ipv4 address
        0x02  : 'NS',    // nameserver
        0x03  : 'MD',    // obsolete
        0x04  : 'MF',    // obsolete
        0x05  : 'CNAME', // alias
        0x06  : 'SOA',   // start of authority
        0x07  : 'MB',    // experimental
        0x08  : 'MG',    // experimental
        0x09  : 'MR',    // experimental
        0x0A  : 'NULL',  // experimental null RR
        0x0B  : 'WKS',   // service description
        0x0C  : 'PTR',   // reverse entry (inaddr.arpa)
        0x0D  : 'HINFO', // host information
        0x0E  : 'MINFO', // mailbox or mail list information
        0x0F  : 'MX',    // mail exchange
        0x10  : 'TXT',   // text strings
        0x1C  : 'AAAA',  // ipv6 address
        0x21  : 'SRV',   // srv records
        0x29  : 'OPT',
        0xF9  : 'TKEY',
        0xFA  : 'TSIG',
        0xFB  : 'IXFR',  // req for incremental transfer
        0xFC  : 'AXFR',  // request to transfer entire zone
        0xFE  : 'MAILA', // request for mailbox related records
        0xFD  : 'MAILB', // request for mail agent RRs
        0xFF  : 'ANY'    // any class
};

module.exports = {
        DNS_ENOERR  : 0x00, // No error
        DNS_EFORMAT : 0x01, // Formatting Error
        DNS_ESERVER : 0x02, // server it unable to process
        DNS_ENONAME : 0x03, // name does not exist
        DNS_ENOTIMP : 0x04, // feature not implemented on this server
        DNS_EREFUSE : 0x05, // refused for policy reasons
        encode: encode,
        decode: decode,
        queryTypes: queryTypes
        opCodes: opCodes
};
