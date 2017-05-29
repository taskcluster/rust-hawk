'use strict';
/** Based on the JS Hawk exampel:
 * https://github.com/hueniverse/hawk/blob/master/example/usage.js */

var Http = require('http');
var Request = require('request');
var Hawk = require('hawk');
var fs = require('fs');
var net = require('net');

var internals = {
  credentials: {
    dh37fgj492je: {
      id: 'dh37fgj492je',                       // Required by Hawk.client.header
      key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
      algorithm: 'sha256',
      user: 'Steve'
    }
  }
};

// Credentials lookup function

var credentialsFunc = function (id, callback) {
  return callback(null, internals.credentials[id]);
};

var server;

// Create HTTP server

var handler = function (req, res) {
  var request_body = "foo=bar"; // TODO: use body-parser
  Hawk.server.authenticate(req,
    credentialsFunc,
    {payload: request_body},
    function (err, credentials, artifacts) {
      var payload = (!err ? 'Hello ' + credentials.user + ' ' + artifacts.ext : 'Shoosh!');
      var headers = {
        'Content-Type': 'text/plain',
        'Server-Authorization': Hawk.server.header(credentials, artifacts, { payload, contentType: 'text/plain' })
      };

      res.writeHead(!err ? 200 : 401, headers);
      res.end(payload);
      server.close();
    });
};

var PORT = parseInt(process.argv[2]);
var CALLBACK_PORT = parseInt(process.argv[3]);

server = Http.createServer(handler).listen(PORT, '127.0.0.1', function() {
  // parent process waits for listening to complete by waiting for a tcp
  // connection on this port
  net.createConnection({port: CALLBACK_PORT, host: "127.0.0.1"}, function() {
    this.end();;
  });
});

