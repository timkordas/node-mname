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
 * using the 'dig' utility, as its the only tool that supports alternative ports
 * when doing a query.
 *
 * When this module is loaded it will return an object containing an array of
 * samples that you can use to test serializers, protocol generators, create a
 * raw DNS client, etc.
 *
 * Each sample is an object with an 'id', 'description', 'raw',  and 'data'.
 * The ID is used so that adding and removing samples out of order will not
 * affect external  references to them in tests.
 *
 * The data is put through an encoder that will turn this string into a raw
 * buffer. That way, samples may be loaded from file that can be read by a
 * (mortal) human being.
 *
 * When the sample is encoded it places a "raw" value in the object. If you
 * have one there it will be over-written.
 */

var samples = [
        {
                id: 0,
                description: 'query ns1.joyent.dev (A)',
                data: "0f 34 81 00 00 01 00 00 00 00 00 00 03 6e 73 31 06 6a 6f 79 65 " +
                        "6e 74 03 64 65 76 00 00 01 00 01",
                type: 'queryMessage'
        },
        {
                id: 1,
                description: 'query ns1.joyent.dev (AAAA)',
                data: "b9 dd 01 00 00 01 00 00 00 00 00 00 03 6e 73 31 06 6a 6f 79 65 " +
                        "6e 74 03 64 65 76 00 00 1c 00 01",
                type: 'queryMessage'
        }
];

function encode(data) {
        var tokens, buffer, pos = 0;

        if (typeof(data) !== 'string')
                throw new TypeError('data (string) is required');

        tokens = data.split(/\s/);
        buffer = new Buffer(tokens.length);

        for (var i = 0; i < tokens.length; ++i) {
                var v = parseInt(tokens[i], 16);
                buffer.writeInt8(v, pos++, true);
        }
        return buffer;
}

function encodeSamples(samps) {
        var sample, results = [];
        for (var i = 0; i < samps.length; ++i) {
                sample = samps[i];
                sample.raw = encode(sample.data);
                results.push(sample);
        }
        return results;
}

function equalBuffers(b1, b2) {
        if (b1.length !== b2.length) {
                return false;
        }

        var l = b1.length;
        while (l--) {
                var one = b1.readUInt8(l);
                var two = b2.readUInt8(l);
                if (one !== two) {
                        return false;
                }
        }
        return true;
}

module.exports = {
        samples: encodeSamples(samples),
        equalBuffers: equalBuffers
};
