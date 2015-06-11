var Http = require('http');
var Hawk = require('hawk');


// Credentials lookup function

var credentialsFunc = function (id, callback) {

    var credentials = {
        key: 'no-secret',
        algorithm: 'sha256',
        user: 'test-client'
    };

    return callback(null, credentials);
};

// Create HTTP server

var handler = function (req, res) {

    // Authenticate incoming request
    console.log("----------");
    console.log(JSON.stringify(req.headers, null, 2));
    Hawk.server.authenticate(req, credentialsFunc, {}, function (err, credentials, artifacts) {

        // Prepare response

        var payload = (!err ? 'Hello ' + credentials.user + ' ' + artifacts.ext : 'Shoosh!');
        var headers = { 'Content-Type': 'text/plain' };

        // Generate Server-Authorization response header

        var header = Hawk.server.header(credentials, artifacts, { payload: payload, contentType: headers['Content-Type'] });
        headers['Server-Authorization'] = header;

        // Send the response back

        res.writeHead(!err ? 200 : 401, headers);
        res.end(payload);
    });
};

// Start server

Http.createServer(handler).listen(8000);
