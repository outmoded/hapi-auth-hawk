### hapi-auth-hawk

[**hapi**](https://github.com/hapijs/hapi) Hawk authentication plugin

[![Build Status](https://secure.travis-ci.org/hapijs/hapi-auth-hawk.png)](http://travis-ci.org/hapijs/hapi-auth-hawk)

Lead Maintainer: [Danny Coates](https://github.com/dannycoates)

#### Hawk authentication

[Hawk authentication](https://github.com/hueniverse/hawk) provides a holder-of-key authentication scheme. The scheme supports payload
authentication. The scheme requires the following options:

- `getCredentialsFunc` - credential lookup function with the signature `[async] function(id)` where:
    - `id` - the Hawk credentials identifier.
    - _throws_ an internal error.
    - _returns_ `{ credentials }` object where:
        - `credentials` a credentials object passed back to the application in `request.auth.credentials`. Set to be `null` or `undefined` to
          indicate unknown credentials (which is not considered an error state).
- `hawk` - optional protocol options passed to `Hawk.server.authenticate()`.

```javascript
const Hapi = require('hapi');

const credentials = {
    d74s3nz2873n: {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256'
    }
};

const getCredentialsFunc = function (id) {

    return credentials[id];
};

const start = async () => {

    const server = Hapi.server({ port: 4000 });

    await server.register(require('hapi-auth-hawk'));

    server.auth.strategy('default', 'hawk', { getCredentialsFunc });
    server.auth.default('default');

    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, h) {

            return 'welcome';
        }
    });

    await server.start();

    console.log('Server started listening on %s', server.info.uri);
};

start();

// Ensure process exits on unhandled rejection

process.on('unhandledRejection', (err) => {

    throw err;
});

```

#### Bewit authentication

[Bewit authentication](https://github.com/hueniverse/hawk#single-uri-authorization) provides a short-term access to a protected resource by
including a token (bewit) in the request query, issued by an authorized party. Bewit is a subset of the Hawk protocol. The scheme can only
be used with 'GET' requests and requires the following options:

- `getCredentialsFunc` - credential lookup function with the signature `async function(id)` where:
    - `id` - the Hawk credentials identifier.
    - _throws_ an internal error.
    - _returns_ `{ credentials }` object where:
        - `credentials` a credentials object passed back to the application in `request.auth.credentials`. Set to be `null` or `undefined` to
      indicate unknown credentials (which is not considered an error state).
- `hawk` - optional protocol options passed to `Hawk.server.authenticateBewit()`.

```javascript
const Hapi = require('hapi');

const credentials = {
    d74s3nz2873n: {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256'
    }
};

const getCredentialsFunc = function (id) {

    return credentials[id];
};

const start = async () => {

    const server = Hapi.server({ port: 4000 });

    await server.register(require('.'));

    server.auth.strategy('default', 'bewit', { getCredentialsFunc });
    server.auth.default('default');

    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, h) {

            return 'welcome';
        }
    });

    await server.start();

    console.log('Server started listening on %s', server.info.uri);
};

start();

// Ensure process exits on unhandled rejection

process.on('unhandledRejection', (err) => {

    throw err;
});
```

To send an authenticated Bewit request, the URI must contain the `'bewit'` query parameter which can be generated using the Hawk module:

```javascript
const Hawk = require('hawk');

const credentials = {
    id: 'd74s3nz2873n',
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'sha256'
};

let uri = 'http://example.com:8080/endpoint';
const bewit = Hawk.client.getBewit(uri, { credentials: credentials, ttlSec: 60 });
uri += '?bewit=' + bewit;
```
