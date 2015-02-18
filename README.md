### hapi-auth-hawk

[**hapi**](https://github.com/hapijs/hapi) Hawk authentication plugin

[![Build Status](https://secure.travis-ci.org/hapijs/hapi-auth-hawk.png)](http://travis-ci.org/hapijs/hapi-auth-hawk)

Lead Maintainer: [Danny Coates](https://github.com/dannycoates)

#### Hawk authentication

[Hawk authentication](https://github.com/hueniverse/hawk) provides a holder-of-key authentication scheme. The scheme supports payload
authentication. The scheme requires the following options:

- `getCredentialsFunc` - credential lookup function with the signature `function(id, callback)` where:
    - `id` - the Hawk credentials identifier.
    - `callback` - the callback function with signature `function(err, credentials)` where:
        - `err` - an internal error.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Return `null` or `undefined` to
          indicate unknown credentials (which is not considered an error state).
- `hawk` - optional protocol options passed to `Hawk.server.authenticate()`.

```javascript
var Hapi = require('hapi');
var HapiHawk = require('hapi-auth-hawk');
var server = new Hapi.Server();
server.connection();

var credentials = {
    d74s3nz2873n: {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256'
    }
}

var getCredentials = function (id, callback) {

    return callback(null, credentials[id]);
};

server.register(HapiHawk, function (err) {

    server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
});

```

#### Bewit authentication

[Bewit authentication](https://github.com/hueniverse/hawk#single-uri-authorization) provides a short-term access to a protected resource by
including a token (bewit) in the request query, issued by an authorized party. Bewit is a subset of the Hawk protocol. The scheme can only
be used with 'GET' requests and requires the following options:

- `getCredentialsFunc` - credential lookup function with the signature `function(id, callback)` where:
    - `id` - the Hawk credentials identifier.
    - `callback` - the callback function with signature `function(err, credentials)` where:
        - `err` - an internal error.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Return `null` or `undefined` to
          indicate unknown credentials (which is not considered an error state).
- `hawk` - optional protocol options passed to `Hawk.server.authenticateBewit()`.

```javascript
var Hapi = require('hapi');
var server = new Hapi.Server();
server.connection();

var credentials = {
    d74s3nz2873n: {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256'
    }
}

var getCredentials = function (id, callback) {

    return callback(null, credentials[id]);
};

server.register('hapi-auth-hawk', function (err) {

    server.auth.strategy('default', 'bewit', { getCredentialsFunc: getCredentials });
});
```

To send an authenticated Bewit request, the URI must contain the `'bewit'` query parameter which can be generated using the Hawk module:

```javascript
var Hawk = require('hawk');

var credentials = {
    id: 'd74s3nz2873n',
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'sha256'
};

var uri = 'http://example.com:8080/endpoint';
var bewit = Hawk.client.getBewit(uri, { credentials: credentials, ttlSec: 60 });
uri += '?bewit=' + bewit;
```
