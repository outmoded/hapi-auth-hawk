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

    const getCredentials = function (id, callback) {

        if (credentials[id]) {
            return callback(credentials[id].err, credentials[id].cred);
        }
        return callback(null, null);
    };

    const hawkHeader = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.client.header('http://example.com:8080' + path, 'POST', { credentials: credentials[id].cred });
        }
        return '';
    };

    it('returns a reply on successful auth', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST', path: '/hawk',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default' }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', '/hawk').field } };
            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on failed optional auth', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST', path: '/hawkOptional',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: { mode: 'optional', strategy: 'default' } }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawkOptional' };
            server.inject(request, (res) => {

                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('includes authorization header in response when the response is a stream', (done) => {

        const hawkStreamHandler = function (request, reply) {

            const TestStream = function () {

                Stream.Readable.call(this);
            };

            Hoek.inherits(TestStream, Stream.Readable);

            TestStream.prototype._read = function (size) {

                if (this.isDone) {
                    return;
                }
                this.isDone = true;

                setTimeout(() => {

                    this.push('hi');
                }, 2);

                setTimeout(() => {

                    this.push(null);
                }, 5);
            };

            const stream = new TestStream();
            reply(stream);
        };

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkStream', handler: hawkStreamHandler, config: { auth: 'default' } });

            const authHeader = hawkHeader('john', '/hawkStream');
            const request = { method: 'POST', url: 'http://example.com:8080/hawkStream', headers: { authorization: authHeader.field } };
            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['server-authorization']).to.contain('Hawk');

                const options = {
                    payload: res.payload
                };

                getCredentials('john', (err, cred) => {

                    const header = Hawk.server.header(cred, authHeader.artifacts, options);
                    expect(header).to.equal(res.headers['server-authorization']);
                    done();
                });
            });
        });
    });

    it('includes valid authorization header in response when the response is text', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST', path: '/hawk',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default'  }
            });

            const authHeader = hawkHeader('john', '/hawk');
            const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: authHeader.field } };

            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['server-authorization']).to.contain('Hawk');

                const options = {
                    payload: res.payload,
                    contentType: res.headers['content-type']
                };

                getCredentials('john', (err, cred) => {

                    const header = Hawk.server.header(cred, authHeader.artifacts, options);
                    expect(header).to.equal(res.headers['server-authorization']);

                    done();
                });
            });
        });
    });

    it('includes valid authorization header in response when the request fails validation', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST', path: '/hawkValidate',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default', validate: { query: {} } }
            });

            const authHeader = hawkHeader('john', '/hawkValidate?a=1');
            const request = { method: 'POST', url: 'http://example.com:8080/hawkValidate?a=1', headers: { authorization: authHeader.field } };
            server.inject(request, (res) => {

                expect(res.headers['server-authorization']).to.exist();
                expect(res.headers['server-authorization']).to.contain('Hawk');
                expect(res.statusCode).to.equal(400);

                const options = {
                    payload: res.payload,
                    contentType: res.headers['content-type']
                };

                getCredentials('john', (err, cred) => {

                    authHeader.artifacts.credentials = cred;
                    const header = Hawk.server.header(cred, authHeader.artifacts, options);
                    expect(header).to.equal(res.headers['server-authorization']);

                    done();
                });
            });
        });
    });

    it('does not include authorization header in response when the response is an error', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST', path: '/hawkError',
                handler: function (request, reply) {

                    reply(new Error());
                },
                config: { auth: 'default' }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawkError', headers: { authorization: hawkHeader('john', '/hawkError').field } };
            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(500);
                expect(res.headers.authorization).to.not.exist();
                done();
            });
        });
    });

    it('returns an error on bad auth header', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawk',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default' }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', 'abcd').field } };
            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('returns an error on bad header format', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST', path: '/hawk',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default' }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk' } };
            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('returns an error on bad scheme', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawk',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default' }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk something' } };
            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('returns an error on insufficient scope', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkScope',
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: { scope: 'x', strategy: 'default'  } }
            });

            const request = { method: 'POST', url: 'http://example.com:8080/hawkScope', payload: 'something', headers: { authorization: hawkHeader('john', '/hawkScope').field } };
            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(403);
                done();
            });
        });
    });

    it('returns a reply on successful auth when using a custom host header key', (done) => {

        const server = new Hapi.Server();
        server.connection();
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
                handler: function (request, reply) {

                    reply('Success');
                },
                config: { auth: 'default' }
            });

            const request = { method: 'POST', url: '/hawk', headers: { authorization: hawkHeader('john', '/hawk').field, custom: 'example.com:8080' } };
            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on successful auth and payload validation', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayload',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayload',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is absent', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayload',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional validation', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayloadOptional',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns a reply on successful auth and payload validation when validation is optional', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayloadOptional',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns a reply on successful auth when payload validation is optional and no payload hash exists', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayloadOptional',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns a reply on successful auth and when payload validation is disabled', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayloadNone',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns a reply on successful auth when the payload is tampered with and the route has disabled validation', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayloadNone',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns a reply on successful auth when auth is optional and when payload validation is required', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkOptionalPayload',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional auth', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkOptionalPayload',
                handler: function (request, reply) {

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
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload hash is not included and payload validation is required', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({
                method: 'POST',
                path: '/hawkPayload',
                handler: function (request, reply) {

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
                done();
            });
        });
    });
});
