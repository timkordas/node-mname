var assert = require('assert-plus');
var dgram = require('dgram');
var net = require('net');
var EventEmitter = require('events').EventEmitter;
var util = require('util');

var Query = require('./query');
var DnsError = require('./errors');



///--- Globals

var sprintf = util.format;

var ExceptionError = DnsError.ExceptionError;
var ProtocolError = DnsError.ProtocolError;



///--- API

function Server(options) {
        assert.object(options, 'options');
        assert.object(options.log, 'options.log');
        assert.optionalString(options.name, 'options.name');

        this._log = options.log.child({component: 'agent'}, true);
        this._name = options.name || "named";
        this._socket = null;

}
util.inherits(Server, EventEmitter);


Server.prototype.close = function close(callback) {
        if (typeof (callback) === 'function')
                this._socket.once('close', callback);

        this._socket.close();
};

Server.prototype.listenTcp = function listenTcp(port, address, callback) {
        assert.number(port, 'port');

        if (typeof (address) === 'function' || !address) {
                callback = address;
                address = '0.0.0.0';
        }
        assert.optionalFunc(callback, 'callback');
        assert.string('address');

        var self = this;
        this._server = net.createServer();
        this._server.listen(port, address);
        this._server.on('close', function onSocketClose() {
                self.emit('close');
        });
        this._server.on('error', function onSocketError(err) {
                self.emit('error', err);
        });
        this._server.on('connection', function(sock) {
                var qbuf = new Buffer(0);
                sock.on('error', function onSocketError(err) {
                        self.emit('error', err);
                });
                sock.on('data', function(data) {
                        qbuf = Buffer.concat([qbuf, data]);

                        if (qbuf.length < 2)
                                return;
                        var len = qbuf.readUInt16BE(0);
                        if (qbuf.length - 2 < len)
                                return;

                        qbuf = qbuf.slice(2);

                        var decoded;
                        var query;
                        var raw = {
                                buf: qbuf,
                                len: qbuf.length
                        };
                        var src = {
                                family: 'tcp',
                                address: sock.remoteAddress,
                                socket: sock
                        };
                        try {
                                decoded = Query.parse(raw, src);
                                query = Query.createQuery(decoded);
                        } catch (e) {
                                self._log.warn({
                                        err: e
                                }, 'query failed to parse');
                                self.emit('clientError',
                                    new ProtocolError('invalid DNS datagram'));
                                return;
                        }

                        if (query === undefined || query === null) {
                                return;
                        }

                        sock.on("end", function() {
                                delete query._client.socket;
                        });
                        sock.on("close", function() {
                                delete query._client.socket;
                        });

                        query.respond = function respond() {
                                self.send(query);
                        };

                        try {
                                self.emit('query', query);
                        } catch (e) {
                                self._log.warn({
                                        err: e
                                }, 'query handler threw an uncaughtException');
                                self.emit('uncaughtException', e);
                        }
                });
                sock.on('close', function() {
                        qbuf = undefined;
                })
        });
        this._server.on('close', function() {
                self.emit('close');
        })
}

Server.prototype.listen = function listen(port, address, callback) {
        assert.number(port, 'port');

        if (typeof (address) === 'function' || !address) {
                callback = address;
                address = '0.0.0.0';
        }
        assert.optionalFunc(callback, 'callback');
        assert.string(address);

        var self = this;

        this._socket = dgram.createSocket('udp6');
        this._socket.once('listening', function () {
                self.emit('listening');
                if (typeof (callback) === 'function')
                        process.nextTick(callback);
        });
        this._socket.on('close', function onSocketClose() {
                self.emit('close');
        });
        this._socket.on('error', function onSocketError(err) {
                self.emit('error', err);
        });
        this._socket.on('message', function (buffer, rinfo) {
                var decoded;
                var query;
                var raw = {
                        buf: buffer,
                        len: rinfo.size
                };

                var src = {
                        family: 'udp6',
                        address: rinfo.address,
                        port: rinfo.port
                };

                try {
                        decoded = Query.parse(raw, src);
                        query = Query.createQuery(decoded);
                } catch (e) {
                        self._log.warn({
                                err: e
                        }, 'query failed to parse');
                        self.emit('clientError',
                            new ProtocolError('invalid DNS datagram'));
                        return;
                }

                if (query === undefined || query === null) {
                        return;
                }

                query.respond = function respond() {
                        self.send(query);
                };

                try {
                        self.emit('query', query);
                } catch (e) {
                        self._log.warn({
                                err: e
                        }, 'query handler threw an uncaughtException');
                        self.emit('uncaughtException', e);
                }
        });
        this._socket.bind(port, address);
};


Server.prototype.send = function send(res) {
        assert.object(res);
        assert.func(res.encode);

        try {
                res._flags.qr = 1;  // replace with function
                res.encode();
        } catch (e) {
                this._log.trace({err: e}, 'send: uncaughtException');
                var err = new ExceptionError('unable to encode response');
                this.emit('uncaughtException', err);
                return false;
        }

        var family = res._client.family;
        switch (family) {
                case 'udp6':
                        var addr = res._client.address;
                        var buf = res._raw.buf;
                        var len = res._raw.len;
                        var port = res._client.port;
                        var self = this;

                        this._log.trace({
                                adddress: addr,
                                port: port,
                                len: len
                        }, 'send: writing DNS message to socket');

                        this._socket.send(buf, 0, len, port, addr, function (err, bytes) {
                                if (err) {
                                        self._log.warn({
                                                adddress: addr,
                                                port: port,
                                                err: err
                                        }, 'send: unable to send response');
                                        self.emit('error', new ExceptionError(err.message));
                                } else {
                                        self._log.trace({
                                                adddress: addr,
                                                port: port
                                        }, 'send: DNS response sent');
                                        self.emit('after', res, bytes);
                                }
                        });
                        break;

                case 'tcp':
                        var sock = res._client.socket;
                        if (!sock) {
                                this._log.debug("send: connection already closed, dropping data");
                                break;
                        }

                        var buf = res._raw.buf;
                        var len = res._raw.len;
                        var self = this;
                        this._log.trace({
                                adddress: sock.remoteAddress,
                                len: len
                        }, 'send: writing DNS message to TCP socket');
                        var lenbuf = new Buffer(2);
                        lenbuf.writeUInt16BE(buf.length, 0);
                        sock.write(Buffer.concat([lenbuf, buf]));

                        res._answers = [];
                        res._qdCount = 0;
                        res._anCount = 0;
                        break;
        }
};


Server.prototype.toString = function toString() {
        var str = '[object named.Server <';
        str += sprintf('name=%s, ', this._name);
        str += sprintf('socket=%j', this._socket ? this._socket.address() : {});
        str += '>]';
        return (str);
};



///--- Exports

module.exports = Server;
