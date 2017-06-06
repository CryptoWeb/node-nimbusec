#!/usr/bin/env node

var nimbusecAPI = require('../lib/index.js');

if (process.argv.length != 7) {
	console.log('Usage : ' + process.argv[0] + ' ' + process.argv[1] + '<key> <secret> <bundle-id> <scheme> <dns-name>');
	process.exit(1);
}

var key = process.argv[2];
var secret = process.argv[3];

var domain = {
	bundle: process.argv[4],
	scheme: process.argv[5],
	name: process.argv[6],
	deepScan: process.argv[5] + '://' + process.argv[6] + '/',
	fastScans: [process.argv[5] + '://' + process.argv[6] + '/']
};

var api = new nimbusecAPI(key, secret);
api.createDomain(domain, function (err, res, details) { // eslint-disable-line

	if (err) {
		console.log('An error occured : ');
		console.log(' - code : ' + err.statusCode);
		console.log(' - message : ' + err.message);
		process.exit(1);
	}

	console.log(res);
});
