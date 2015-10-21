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

Server.prototype.listenTcp = function listenTcp(opts, callback) {
        assert.object(opts, 'options');
        assert.number(opts.port, 'port');
        if (opts.address === undefined)
                opts.address = '0.0.0.0';
        assert.string(opts.address, 'address');
        assert.optionalFunc(callback, 'callback');

        var self = this;
        assert.strictEqual(this._server, undefined,
            'listenTcp can only be called once');
        this._server = net.createServer();
        this._server.listen(opts.port, opts.address, callback);
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

                        var query;
                        var qopts = {
                                family: 'tcp',
                                address: sock.remoteAddress,
                                socket: sock,
                                data: qbuf
                        };
                        try {
                                query = Query.parse(qopts);
                        } catch (e) {
                                if (self.listenerCount('clientError') <= 0) {
                                    self._log.warn({
                                            err: e
                                    }, 'query failed to parse');
                                } else {
                                    var err = new ProtocolError(
                                        'invalid DNS datagram');
                                    err.client = {
                                        address: sock.remoteAddress
                                    };
                                    err.innerError = e;
                                    self.emit('clientError', err);
                                }
                                return;
                        }

                        if (query === undefined || query === null) {
                                return;
                        }

                        sock.on("end", function() {
                                delete query.src.socket;
                        });
                        sock.on("close", function() {
                                delete query.src.socket;
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
                                self.emit('error', e);
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

Server.prototype.listenUdp = function listenUdp(opts, callback) {
        assert.object(opts, 'options');
        assert.number(opts.port, 'port');
        if (opts.address === undefined)
                opts.address = '0.0.0.0';
        assert.string(opts.address, 'address');
        if (opts.family === undefined)
                opts.family = 'udp6';
        assert.string(opts.family, 'family');
        assert.optionalFunc(callback, 'callback');

        var self = this;
        assert.strictEqual(this._socket, null,
            'listen can only be called once');

        this._socket = dgram.createSocket(opts.family);
        this._socket.once('listening', function () {
                self.emit('listening');
                if (typeof (callback) === 'function')
                        process.nextTick(callback);
        });
        this._socket.on('close', function onSocketClose() {
                self.emit('close');
        });
        this._socket.on('error', function onSocketError(err) {
                if (self._socket.bound || opts.family === 'udp4') {
                        self.emit('error', err);
                } else {
                        if (err.code && err.code === 'EINVAL') {
                                self._log.debug({err: err},
                                    '%s socket failed to bind, falling ' +
                                    'back to udp4', opts.family);
                                delete (self._socket);
                                self._socket = null;
                                var opts2 = {family: 'udp4'};
                                Object.setPrototypeOf(opts2, opts);
                                self.listenUdp(opts2, callback);
                        } else {
                                self.emit('error', err);
                        }
                }
        });
        this._socket.on('message', function (buffer, rinfo) {
                var query;

                var qopts = {
                        family: 'udp',
                        address: rinfo.address,
                        port: rinfo.port,
                        data: buffer
                };

                try {
                        query = Query.parse(qopts);
                } catch (e) {
                        if (self.listenerCount('clientError') <= 0) {
                            self._log.warn({
                                    err: e
                            }, 'query failed to parse');
                        } else {
                            var err = new ProtocolError(
                                'invalid DNS datagram');
                            err.client = {
                                address: rinfo.address,
                                port: rinfo.port
                            };
                            err.innerError = e;
                            self.emit('clientError', err);
                        }
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
                        self.emit('error', e);
                }
        });
        this._socket.bind(opts.port, opts.address, function () {
                self._socket.bound = true;
        });
};

Server.prototype.listen = function listen(port, address, callback) {
        var opts = {};
        opts.port = port;
        if (typeof (address) === 'function')
                callback = address;
        else
                opts.address = address;
        return (this.listenUdp(opts, callback));
}


Server.prototype.send = function send(res) {
        assert.object(res);

        assert.func(res.encode);

        assert.object(res.src);
        assert.string(res.src.address);
        assert.string(res.src.family);

        var buf = res.encode();

        var family = res.src.family;
        switch (family) {
                case 'udp':
                        assert.number(res.src.port);

                        var addr = res.src.address;
                        var len = buf.length;
                        var port = res.src.port;
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
                        var sock = res.src.socket;
                        if (!sock) {
                                this._log.debug("send: connection already closed, dropping data");
                                break;
                        }

                        var len = buf.length;
                        var self = this;
                        this._log.trace({
                                adddress: sock.remoteAddress,
                                len: len
                        }, 'send: writing DNS message to TCP socket');
                        var lenbuf = new Buffer(2);
                        lenbuf.writeUInt16BE(buf.length, 0);
                        sock.write(Buffer.concat([lenbuf, buf]));

                        res.reset();
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
