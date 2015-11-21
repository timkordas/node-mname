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

module.exports = DNSBuffer;

var assert = require('assert-plus');

function DNSBuffer(opts) {
        assert.object(opts, 'options');
        if (opts.buffer !== undefined)
                assert.buffer(opts.buffer, 'options.buffer');

        this._size = opts.buffer ? opts.buffer.length : 1024;
        this._buffer = opts.buffer || (new Buffer(this._size));
        this._offset = 0;
        this._ncache = new NameOffsetCache();
}

DNSBuffer.prototype.toBuffer = function () {
        return (this._buffer.slice(0, this._offset));
};

DNSBuffer.prototype.atEnd = function () {
        return (this._offset >= this._buffer.length);
};

DNSBuffer.prototype.remainder = function () {
        return (this._buffer.slice(this._offset));
};

DNSBuffer.prototype.skip = function (n) {
        this._offset += n;
};

DNSBuffer.prototype.expand = function () {
        this._size *= 2;
        var buf = new Buffer(this._size);
        this._buffer.copy(buf, 0);
        this._buffer = buf;
};

DNSBuffer.prototype.readUInt32 = function () {
        var v = this._buffer.readUInt32BE(this._offset);
        this._offset += 4;
        return (v);
};

DNSBuffer.prototype.readUInt16 = function () {
        var v = this._buffer.readUInt16BE(this._offset);
        this._offset += 2;
        return (v);
};

DNSBuffer.prototype.readUInt8 = function () {
        var v = this._buffer[this._offset++];
        return (v);
};

DNSBuffer.prototype.readLengthPrefixed = function (lenBytes, cb) {
        assert.ok(lenBytes === 1 || lenBytes === 2 || lenBytes === 4);

        var len = this._buffer.readUIntBE(this._offset, lenBytes);
        this._offset += lenBytes;

        var child = Object.create(this);
        child._size = len;
        var ret = cb(child);
        this._offset += len;

        return (ret);
};

var NAME_META_MASK = 0xC0;
var NAME_STRING = 0x00;
var NAME_PTR = 0xC0;

DNSBuffer.prototype.readName = function () {
        var rlen, name = [];

        rlen = this.readUInt8();
        while (rlen !== 0x00) {
                var meta = rlen & NAME_META_MASK;

                if (meta == NAME_STRING) {
                        var buf = this._buffer.slice(this._offset,
                            this._offset + rlen);
                        this._offset += rlen;
                        name.push(buf.toString('ascii'));

                } else if (meta == NAME_PTR) {
                        var ptr = this.readUInt8();
                        ptr = ptr | ((rlen & ~(0xC0)) << 8);

                        var clone = Object.create(this);
                        clone._offset = ptr;
                        name.push(clone.readName());
                        break;

                } else {
                        throw (new Error('Invalid name segment type: ' + meta));
                }

                rlen = this.readUInt8();
        }

        return (name.join('.'));
};

DNSBuffer.prototype.writeName = function (name) {
        assert.string(name, 'name');

        if (name === '' || name === '.') {
                this.writeUInt8(0);
                return;
        }
        var parts = name.split('.');

        var suffix = this._ncache.getSuffix(parts);
        if (suffix.remainder !== undefined)
                parts = suffix.remainder;

        var rlen;
        while (parts.length > 0) {
                /* Can only use ptrs to things in the first 0xc000 bytes. */
                if (this._offset < 0xc000)
                        this._ncache.add(parts, this._offset);

                var part = parts.shift();
                rlen = part.length;
                assert.ok(rlen < 64, 'segment "' + part + '" of name "' +
                    name + '" is too long');
                this.writeUInt8(rlen);
                this.write(new Buffer(part, 'ascii'));
        }

        if (suffix.offset !== undefined) {
                assert.ok(suffix.offset < 0xc000);

                var ptr = suffix.offset & 0xff;
                rlen = NAME_PTR | ((suffix.offset & 0x3f00) >> 8);
                this.writeUInt8(rlen);
                this.writeUInt8(ptr);

        } else {
                this.writeUInt8(0);
        }
};

DNSBuffer.prototype.writeUInt32 = function (v) {
        while (this._offset + 4 > this._size)
                this.expand();
        this._buffer.writeUInt32BE(v % 0xffffffff, this._offset);
        this._offset += 4;
};

DNSBuffer.prototype.writeUInt16 = function (v) {
        while (this._offset + 2 > this._size)
                this.expand();
        this._buffer.writeUInt16BE(v & 0xffff, this._offset);
        this._offset += 2;
};

DNSBuffer.prototype.writeUInt8 = function (v) {
        while (this._offset + 1 > this._size)
                this.expand();
        this._buffer[this._offset++] = v & 0xff;
};

DNSBuffer.prototype.write = function (buf) {
        while (this._offset + buf.length > this._size)
                this.expand();
        buf.copy(this._buffer, this._offset);
        this._offset += buf.length;
};

DNSBuffer.prototype.writeLengthPrefixed = function (lenBytes, cb) {
        assert.ok(lenBytes === 1 || lenBytes === 2 || lenBytes === 4);

        var lenOffset = this._offset;
        this._offset += lenBytes;
        var ret = cb(this);
        var len = this._offset - lenOffset - lenBytes;
        this._buffer.writeUIntBE(len, lenOffset, lenBytes);

        return (ret);
};


function NameOffsetCache() {
        this.root = {};
}

NameOffsetCache.prototype.add = function (parts, offset) {
        var node = this.root;
        for (var i = parts.length - 1; i >= 0; --i) {
                if (node[parts[i]] === undefined)
                        node[parts[i]] = {};
                node = node[parts[i]];
        }
        if (node.offset === undefined)
                node.offset = offset;
};

NameOffsetCache.prototype.getSuffix = function (parts) {
        var node = this.root;
        var rem = parts.slice();
        var longest = {};
        while (rem.length > 0) {
                var part = rem.pop();
                if (node[part] === undefined)
                        break;
                node = node[part];
                if (node.offset !== undefined) {
                        longest.remainder = rem.slice();
                        longest.offset = node.offset;
                }
        }
        return (longest);
};
