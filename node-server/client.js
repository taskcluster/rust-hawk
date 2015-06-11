var Request = require('request');
var Hawk = require('hawk');


// Client credentials

var credentials = {
    id: 'test-client',
    key: 'no-secret',
    algorithm: 'sha256'
}

// Request options

var requestOptions = {
    uri: 'http://localhost:8000/resource/1?b=1&a=2',
    method: 'GET',
    headers: {}
};

// Generate Authorization request header

var header = Hawk.client.header('http://localhost:8000/resource/1?b=1&a=2', 'GET', { credentials: credentials, ext: 'some-app-data' });
requestOptions.headers.Authorization = header.field;

// Send authenticated request

Request(requestOptions, function (error, response, body) {

    // Authenticate the server's response

    var isValid = Hawk.client.authenticate(response, credentials, header.artifacts, { payload: body });

    // Output results

    console.log(response.statusCode + ': ' + body + (isValid ? ' (valid)' : ' (invalid)'));
});
