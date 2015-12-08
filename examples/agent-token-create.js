#!/usr/bin/env node

var nimbusecAPI = require('../lib/index.js');

if (process.argv.length != 5) {
    console.log('Usage : ' + process.argv[0] + ' ' + process.argv[1] + '<key> <secret> <name>');
    process.exit(1);
}

var key = process.argv[2];
var secret = process.argv[3];
var agentToken = {
    name: process.argv[4]
};

var api = new nimbusecAPI(key, secret);
api.createAgentToken(agentToken, function(err, res) {

    if (err) {
        console.log('An error occured : ');
        console.log(' - code : '+ err.statusCode);
        console.log(' - message : '+ err.message);
        process.exit(1);
    }

    console.log(res);
});
