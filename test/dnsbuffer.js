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
                type: 'message'
        },
        {
                id: 1,
                description: 'query ns1.joyent.dev (AAAA)',
                data: "b9 dd 01 00 00 01 00 00 00 00 00 00 03 6e 73 31 06 6a 6f 79 65 " +
                        "6e 74 03 64 65 76 00 00 1c 00 01",
                type: 'message'
        },
        {
                id: 2,
                description: 'ptr dns-sd',
                data: 'c4 2f 01 00 00 01 00 00 00 00 00 00 02 6c 62 07 ' +
                      '5f 64 6e 73 2d 73 64 04 5f 75 64 70 01 30 01 34 ' +
                      '02 32 30 03 31 37 32 07 69 6e 2d 61 64 64 72 04 ' +
                      '61 72 70 61 00 00 0c 00 01',
                type: 'message'
        },
        {
                id: 3,
                description: 'txt response',
                data:   '4c 91 85 00 00 01 00 02 00 03 00 06 07 63 6f 6f ' +
                        '70 65 72 69 03 6e 65 74 00 00 10 00 01 c0 0c 00 ' +
                        '10 00 01 00 00 1c 20 00 3a 39 76 3d 73 70 66 31 ' +
                        '20 6d 78 20 6d 78 3a 73 6f 72 75 73 2e 63 6f 6f ' +
                        '70 65 72 69 2e 6e 65 74 20 6d 78 3a 6c 61 6d 69 ' +
                        '6e 61 2e 63 6f 6f 70 65 72 69 2e 6e 65 74 20 2d ' +
                        '61 6c 6c c0 0c 00 10 00 01 00 00 1c 20 00 6d 6c ' +
                        '74 69 6e 66 6f 69 6c 2d 73 69 74 65 2d 76 65 72 ' +
                        '69 66 69 63 61 74 69 6f 6e 3a 20 32 64 37 63 32 ' +
                        '61 32 38 34 35 36 64 31 66 66 36 66 32 64 65 39 ' +
                        '39 61 66 36 32 34 32 39 30 37 65 35 61 61 31 66 ' +
                        '66 31 63 3d 61 36 34 37 32 61 30 32 32 31 33 31 ' +
                        '37 33 66 32 35 31 31 66 32 36 39 62 66 63 31 36 ' +
                        '39 34 61 31 30 39 39 35 63 30 36 38 c0 0c 00 02 ' +
                        '00 01 00 00 1c 20 00 09 06 6c 61 6d 69 6e 61 c0 ' +
                        '0c c0 0c 00 02 00 01 00 00 1c 20 00 08 05 78 79 ' +
                        '6c 65 6d c0 0c c0 0c 00 02 00 01 00 00 1c 20 00 ' +
                        '08 05 73 74 69 70 65 c0 0c c1 11 00 01 00 01 00 ' +
                        '00 1c 20 00 04 a8 eb 56 ec c1 11 00 1c 00 01 00 ' +
                        '00 1c 20 00 10 26 04 01 80 00 03 07 c2 00 00 00 ' +
                        '00 00 00 e5 6a c0 fd 00 01 00 01 00 00 1c 20 00 ' +
                        '04 73 92 4c 41 c0 fd 00 1c 00 01 00 00 1c 20 00 ' +
                        '10 24 02 74 00 50 08 00 01 00 00 00 00 00 00 00 ' +
                        '04 c0 e8 00 01 00 01 00 00 1c 20 00 04 96 6b 48 ' +
                        '5a c0 e8 00 1c 00 01 00 00 1c 20 00 10 24 04 94 ' +
                        '00 00 02 00 00 02 16 3e ff fe f0 33 74',
                type: 'message'
        },
        {
                id: 4,
                description: 'mx response',
                data:   'dd 08 85 00 00 01 00 02 00 03 00 08 07 63 6f 6f ' +
                        '70 65 72 69 03 6e 65 74 00 00 0f 00 01 c0 0c 00 ' +
                        '0f 00 01 00 00 1c 20 00 0b 00 14 06 6c 61 6d 69 ' +
                        '6e 61 c0 0c c0 0c 00 0f 00 01 00 00 1c 20 00 0a ' +
                        '00 0a 05 73 6f 72 75 73 c0 0c c0 0c 00 02 00 01 ' +
                        '00 00 1c 20 00 08 05 73 74 69 70 65 c0 0c c0 0c ' +
                        '00 02 00 01 00 00 1c 20 00 08 05 78 79 6c 65 6d ' +
                        'c0 0c c0 0c 00 02 00 01 00 00 1c 20 00 02 c0 2b ' +
                        'c0 42 00 01 00 01 00 00 1c 20 00 04 c0 c6 5e 65 ' +
                        'c0 42 00 1c 00 01 00 00 1c 20 00 10 26 07 56 00 ' +
                        '01 68 00 00 00 00 00 00 00 00 00 0a c0 2b 00 01 ' +
                        '00 01 00 00 1c 20 00 04 96 6b 48 5a c0 2b 00 1c ' +
                        '00 01 00 00 1c 20 00 10 24 04 94 00 00 02 00 00 ' +
                        '02 16 3e ff fe f0 33 74 c0 56 00 01 00 01 00 00 ' +
                        '1c 20 00 04 a8 eb 56 ec c0 56 00 1c 00 01 00 00 ' +
                        '1c 20 00 10 26 04 01 80 00 03 07 c2 00 00 00 00 ' +
                        '00 00 e5 6a c0 6a 00 01 00 01 00 00 1c 20 00 04 ' +
                        '73 92 4c 41 c0 6a 00 1c 00 01 00 00 1c 20 00 10 ' +
                        '24 02 74 00 50 08 00 01 00 00 00 00 00 00 00 04',
                type: 'message'
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
