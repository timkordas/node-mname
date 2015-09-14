var named = require('../lib/index');
var bunyan = require('bunyan');
var log = bunyan.createLogger({name: 'test'});

var server = named.createServer();
var ttl = 3600;

server.listen(9953, '127.0.0.1');
server.listenTcp(9953, '127.0.0.1');

server.on('query', function(query) {
	var domain = query.name();
	log.info({name: query.name(), type: query.type()});

	if (query.type() === 'AXFR') {
		var soa = new named.SOARecord(domain, {serial: 12345});
		query.addAnswer(domain, soa, ttl);
		server.send(query);

		var a = new named.ARecord("1.2.3.4");
		var a2 = new named.ARecord("1.2.3.5");
		query.addAnswer("foo." + domain, a, ttl);
		query.addAnswer("bar." + domain, a, ttl);
		query.addAnswer("foobar." + domain, a2, ttl);
		server.send(query);

		query.addAnswer(domain, soa, ttl);
		server.send(query);

	} else if (query.type() === 'IXFR') {
		var base = query.ixfrBase();
		var oldSoa = new named.SOARecord(domain, {serial: base});
		var newSoa = new named.SOARecord(domain, {serial: 12345});
		query.addAnswer(domain, newSoa, ttl);
		server.send(query);

		var a = new named.ARecord("1.2.3.4");
		var a2 = new named.ARecord("1.2.3.5");

		/* removed since old serial */
		query.addAnswer(domain, oldSoa, ttl);
		server.send(query);
		query.addAnswer("tri." + domain, a, ttl);

		/* new additions */
		query.addAnswer(domain, newSoa, ttl);
		query.addAnswer("foo." + domain, a, ttl);
		query.addAnswer("bar." + domain, a, ttl);
		query.addAnswer("foobar." + domain, a2, ttl);
		server.send(query);

		query.addAnswer(domain, newSoa, ttl);
		server.send(query);
	}
});
