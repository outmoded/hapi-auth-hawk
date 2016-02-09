'use strict';

// Load modules

const Stream = require('stream');
const Boom = require('boom');
const Code = require('code');
const Hapi = require('hapi');
const Hawk = require('hawk');
const Hoek = require('hoek');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;

internals.initServer = (callback) => {

    const server = new Hapi.Server();
    server.connection();
    callback(server);
};

describe('hawk scheme', () => {

    const credentials = {
        'john': {
            cred: {
                id: 'john',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            }
        },
        'jane': {
            err: Boom.internal('boom')
        },
        'joan': {
            cred: {
                id: 'joan',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            }
        }
    };

    const getCredentials = (id, callback) => {

        if (credentials[id]) {
            return callback(credentials[id].err, credentials[id].cred);
        }
        return callback(null, null);
    };

    const hawkHeader = (id, path) => {

        if (credentials[id] && credentials[id].cred) {

            const header = Hawk.client.header('http://example.com:8080' + path, 'POST', { credentials: credentials[id].cred });
            return  header;
        }
        return '';
    };

    it('returns a reply on successful auth', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST', path: '/hawk',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default' }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', '/hawk').field } };
                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on failed optional auth', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST', path: '/hawkOptional',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'optional', strategy: 'default' } }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawkOptional' };
                server.inject(request, (res) => {

                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('includes authorization trailer in response when the response is a stream', (done) => {

        internals.initServer((server) => {

            const hawkStreamHandler = (request, reply) => {

                const TestStream = function (){

                    Stream.Readable.call(this);
                };

                Hoek.inherits(TestStream, Stream.Readable);

                TestStream.prototype._read = function (size) {

                    const self = this;

                    if (this.isDone) {
                        return;
                    }
                    this.isDone = true;

                    setTimeout(() => {

                        self.push('hi');
                    }, 2);

                    setTimeout(() => {

                        self.push(null);
                    }, 5);
                };

                const stream = new TestStream();
                reply(stream);
            };

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });

                server.route({
                    method: 'POST',
                    path: '/hawkStream',
                    handler: hawkStreamHandler,
                    config: { auth: 'default' }
                });

                const authHeader = hawkHeader('john', '/hawkStream');

                const request = { method: 'POST', url: 'http://example.com:8080/hawkStream', headers: { authorization: authHeader.field } };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);


                    expect(res.trailers['server-authorization']).to.contain('Hawk');

                    const options = {
                        payload: res.payload
                    };

                    getCredentials('john', (err, cred) => {

                        expect(err).to.not.exist();
                        const header = Hawk.server.header(cred, authHeader.artifacts, options);

                        // shot v3 trailers goes to trailers but v1 goes to headers.

                        expect(header).to.equal(res.trailers['server-authorization']);
                        server.stop(done);
                    });
                });
            });
        });
    });

    it('includes valid authorization trailer in response when the response is text', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST', path: '/hawk',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default'  }
                });

                const authHeader = hawkHeader('john', '/hawk');
                const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: authHeader.field } };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);

                    // shot v3 trailers goes to trailers but v1 goes to headers.
                    // expect(res.headers['server-authorization']).to.contain('Hawk');

                    expect(res.trailers['server-authorization']).to.contain('Hawk');

                    const options = {
                        payload: res.payload,
                        contentType: res.headers['content-type']
                    };

                    getCredentials('john', (err, cred) => {

                        expect(err).to.not.exist();

                        const header = Hawk.server.header(cred, authHeader.artifacts, options);

                        expect(header).to.equal(res.trailers['server-authorization']);
                        server.stop(done);
                    });
                });
            });
        });
    });

    it('includes valid authorization trailer in response when the request fails validation', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST', path: '/hawkValidate',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default', validate: { query: {} } }
                });

                const authHeader = hawkHeader('john', '/hawkValidate?a=1');
                const request = { method: 'POST', url: 'http://example.com:8080/hawkValidate?a=1', headers: { authorization: authHeader.field } };
                server.inject(request, (res) => {

                    // shot v3 trailers goes to trailers but v1 goes to headers.
                    // expect(res.headers['server-authorization']).to.contain('Hawk');

                    expect(res.trailers['server-authorization']).to.exist();
                    expect(res.trailers['server-authorization']).to.contain('Hawk');
                    expect(res.statusCode).to.equal(400);

                    const options = {
                        payload: res.payload,
                        contentType: res.headers['content-type']
                    };

                    getCredentials('john', (err, cred) => {

                        expect(err).to.not.exist();

                        authHeader.artifacts.credentials = cred;
                        const header = Hawk.server.header(cred, authHeader.artifacts, options);

                        // expect(header).to.equal(res.headers['server-authorization']);
                        expect(header).to.equal(res.trailers['server-authorization']);

                        server.stop(done);
                    });
                });
            });
        });
    });

    it('does not include authorization header in response when the response is an error', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST', path: '/hawkError',
                    handler: (request, reply) => {

                        reply(new Error());
                    },
                    config: { auth: 'default' }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawkError', headers: { authorization: hawkHeader('john', '/hawkError').field } };
                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(500);
                    expect(res.headers.authorization).to.not.exist();
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error on bad auth header', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawk',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default' }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', 'abcd').field } };
                server.inject(request, (res) => {

                    expect(res.result).to.exist();
                    expect(res.statusCode).to.equal(401);
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error on bad header format', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST', path: '/hawk',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default' }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk' } };
                server.inject(request, (res) => {

                    expect(res.result).to.exist();
                    expect(res.statusCode).to.equal(401);
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error on bad scheme', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawk',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default' }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk something' } };
                server.inject(request, (res) => {

                    expect(res.result).to.exist();
                    expect(res.statusCode).to.equal(401);
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error on insufficient scope', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkScope',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { scope: 'x', strategy: 'default'  } }
                });

                const request = { method: 'POST', url: 'http://example.com:8080/hawkScope', payload: 'something', headers: { authorization: hawkHeader('john', '/hawkScope').field } };
                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(403);
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth when using a custom host header key', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'hawk', {
                    getCredentialsFunc: getCredentials,
                    hawk: {
                        hostHeaderName: 'custom'
                    }
                });

                server.route({
                    method: 'POST',
                    path: '/hawk',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: 'default' }
                });

                const request = { method: 'POST', url: '/hawk', headers: { authorization: hawkHeader('john', '/hawk').field, custom: 'example.com:8080' } };
                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth and payload validation', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayload',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                const payload = 'application text formatted payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload: payload, contentType: 'text/plain' });
                const request = {
                    method: 'POST',
                    url: 'http://example.com:8080/hawkPayload',
                    headers: { authorization: authHeader.field, 'content-type': 'text/plain' },
                    payload: payload,
                    simulate: { split: true }
                };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayload',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                let payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
                payload += 'HACKED';
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).to.equal('Payload is invalid');
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error with payload validation when the payload is absent', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayload',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                let payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
                payload = '';
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).to.equal('Payload is invalid');
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional validation', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayloadOptional',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'optional', strategy: 'default' }, payload: { override: 'text/plain' } }
                });

                let payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred, payload: payload });
                payload += 'HACKED';
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).to.equal('Payload is invalid');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth and payload validation when validation is optional', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayloadOptional',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'optional', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                const payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred, payload: payload });
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.result).to.exist();
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth when payload validation is optional and no payload hash exists', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayloadOptional',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'optional', strategy: 'default'  }, payload: { override: 'text/plain' } } }
                );

                const payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred });
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.result).to.exist();
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth and when payload validation is disabled', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayloadNone',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: false, strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                const payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadNone', 'POST', { credentials: credentials.john.cred, payload: payload });
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadNone', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth when the payload is tampered with and the route has disabled validation', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayloadNone',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: false, strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                let payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadNone', 'POST', { credentials: credentials.john.cred, payload: payload });
                payload += 'HACKED';
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadNone', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns a reply on successful auth when auth is optional and when payload validation is required', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkOptionalPayload',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'optional', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                const payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkOptionalPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
                const request = { method: 'POST', url: 'http://example.com:8080/hawkOptionalPayload', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('Success');
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional auth', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkOptionalPayload',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'optional', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                let payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkOptionalPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
                payload += 'HACKED';
                const request = { method: 'POST', url: 'http://example.com:8080/hawkOptionalPayload', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).to.equal('Payload is invalid');
                    server.stop(done);
                });
            });
        });
    });

    it('returns an error with payload validation when the payload hash is not included and payload validation is required', (done) => {

        internals.initServer((server) => {

            server.register(require('../'), (err) => {

                expect(err).to.not.exist();
                server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
                server.route({
                    method: 'POST',
                    path: '/hawkPayload',
                    handler: (request, reply) => {

                        reply('Success');
                    },
                    config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
                });

                const payload = 'Here is my payload';
                const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred });
                const request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.field }, payload: payload };

                server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).to.equal('Missing payload authentication');
                    server.stop(done);
                });
            });
        });
    });
});
