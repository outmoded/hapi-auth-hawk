'use strict';

const Stream = require('stream');

const Boom = require('boom');
const Code = require('code');
const Hapi = require('hapi');
const Hawk = require('hawk');
const Lab = require('lab');


const internals = {};


const { it, describe } = exports.lab = Lab.script();
const expect = Code.expect;


describe('hawk scheme', () => {

    const credentials = {
        john: {
            cred: {
                id: 'john',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            }
        },
        jane: {
            err: Boom.internal('boom')
        },
        joan: {
            cred: {
                id: 'joan',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            }
        }
    };

    const getCredentialsFunc = function (id) {

        if (credentials[id]) {
            if (credentials[id].err) {
                throw credentials[id].err;
            }

            return credentials[id].cred;
        }
    };

    const hawkHeader = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.client.header('http://example.com:8080' + path, 'POST', { credentials: credentials[id].cred });
        }

        return '';
    };

    it('calls through to handler on successful auth', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default' }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', '/hawk').header } };
        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('calls through to handler on failed optional auth', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkOptional',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'optional', strategy: 'default' } }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawkOptional' };
        const res = await server.inject(request);

        expect(res.result).to.equal('Success');
    });

    it('includes authorization header in response when the response is a stream', async () => {

        const hawkStreamHandler = function (request, h) {

            const TestStream = class extends Stream.Readable {

                _read(size) {

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
                }
            };

            const stream = new TestStream();
            return stream;
        };

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({ method: 'POST', path: '/hawkStream', handler: hawkStreamHandler, options: { auth: 'default' } });

        const authHeader = hawkHeader('john', '/hawkStream');
        const request = { method: 'POST', url: 'http://example.com:8080/hawkStream', headers: { authorization: authHeader.header } };
        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.trailers['server-authorization']).to.contain('Hawk');

        const options = {
            payload: res.payload
        };

        const cred = getCredentialsFunc('john');

        const header = Hawk.server.header(cred, authHeader.artifacts, options);
        expect(header).to.equal(res.trailers['server-authorization']);
    });

    it('includes valid authorization header in response when the response is text', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default'  }
        });

        const authHeader = hawkHeader('john', '/hawk');
        const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: authHeader.header } };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.trailers['server-authorization']).to.contain('Hawk');

        const options = {
            payload: res.payload,
            contentType: res.headers['content-type']
        };

        const cred = getCredentialsFunc('john');

        const header = Hawk.server.header(cred, authHeader.artifacts, options);
        expect(header).to.equal(res.trailers['server-authorization']);
    });

    it('removes the content-length header when switching to chunked transfer encoding', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default'  }
        });

        const authHeader = hawkHeader('john', '/hawk');
        const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: authHeader.header } };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.headers['transfer-encoding']).to.equal('chunked');
        expect(res.headers['content-length']).to.not.exist();
    });

    it('includes valid authorization header in response when the request fails validation', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkValidate',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default', validate: { query: {} } }
        });

        const authHeader = hawkHeader('john', '/hawkValidate?a=1');
        const request = { method: 'POST', url: 'http://example.com:8080/hawkValidate?a=1', headers: { authorization: authHeader.header } };
        const res = await server.inject(request);

        expect(res.trailers['server-authorization']).to.exist();
        expect(res.trailers['server-authorization']).to.contain('Hawk');
        expect(res.statusCode).to.equal(400);

        const options = {
            payload: res.payload,
            contentType: res.headers['content-type']
        };

        const cred = getCredentialsFunc('john');

        authHeader.artifacts.credentials = cred;
        const header = Hawk.server.header(cred, authHeader.artifacts, options);
        expect(header).to.equal(res.trailers['server-authorization']);
    });

    it('does not include authorization header in response when the response is an error', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkError',
            handler: function (request, h) {

                return new Error();
            },
            options: { auth: 'default' }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawkError', headers: { authorization: hawkHeader('john', '/hawkError').header } };
        const res = await server.inject(request);

        expect(res.statusCode).to.equal(500);
        expect(res.headers.authorization).to.not.exist();
    });

    it('returns an error on bad auth header', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default' }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', 'abcd').header } };
        const res = await server.inject(request);

        expect(res.result).to.exist();
        expect(res.statusCode).to.equal(401);
    });

    it('returns an error on bad header format', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default' }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk' } };
        const res = await server.inject(request);

        expect(res.result).to.exist();
        expect(res.statusCode).to.equal(401);
    });

    it('returns an error on bad scheme', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default' }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk something' } };
        const res = await server.inject(request);

        expect(res.result).to.exist();
        expect(res.statusCode).to.equal(401);
    });

    it('returns an error on insufficient scope', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkScope',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { scope: 'x', strategy: 'default'  } }
        });

        const request = { method: 'POST', url: 'http://example.com:8080/hawkScope', payload: '{}', headers: { authorization: hawkHeader('john', '/hawkScope').header } };
        const res = await server.inject(request);

        expect(res.statusCode).to.equal(403);
    });

    it('returns a reply on successful auth when using a custom host header key', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', {
            getCredentialsFunc,
            hawk: {
                hostHeaderName: 'custom'
            }
        });

        server.route({
            method: 'POST',
            path: '/hawk',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: 'default' }
        });

        const request = { method: 'POST', url: '/hawk', headers: { authorization: hawkHeader('john', '/hawk').header, custom: 'example.com:8080' } };
        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('returns a reply on successful auth and payload validation', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayload',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        const payload = 'application text formatted payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload, contentType: 'text/plain' });
        const request = {
            method: 'POST',
            url: 'http://example.com:8080/hawkPayload',
            headers: { authorization: authHeader.header, 'content-type': 'text/plain' },
            payload,
            simulate: { split: true }
        };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('returns an error with payload validation when the payload is tampered with', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayload',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        let payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload });
        payload += 'HACKED';
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(401);
        expect(res.result.message).to.equal('Payload is invalid');
    });

    it('returns an error with payload validation when the payload is absent', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayload',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        let payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload });
        payload = '';
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(401);
        expect(res.result.message).to.equal('Payload is invalid');
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional validation', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayloadOptional',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'optional', strategy: 'default' }, payload: { override: 'text/plain' } }
        });

        let payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred, payload });
        payload += 'HACKED';
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(401);
        expect(res.result.message).to.equal('Payload is invalid');
    });

    it('returns a reply on successful auth and payload validation when validation is optional', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayloadOptional',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'optional', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        const payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred, payload });
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.result).to.exist();
        expect(res.result).to.equal('Success');
    });

    it('returns a reply on successful auth when payload validation is optional and no payload hash exists', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayloadOptional',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'optional', strategy: 'default'  }, payload: { override: 'text/plain' } } }
        );

        const payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred });
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.result).to.exist();
        expect(res.result).to.equal('Success');
    });

    it('returns a reply on successful auth and when payload validation is disabled', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayloadNone',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: false, strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        const payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadNone', 'POST', { credentials: credentials.john.cred, payload });
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadNone', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('returns a reply on successful auth when the payload is tampered with and the route has disabled validation', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayloadNone',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: false, strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        let payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadNone', 'POST', { credentials: credentials.john.cred, payload });
        payload += 'HACKED';
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadNone', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('returns a reply on successful auth when auth is optional and when payload validation is required', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkOptionalPayload',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'optional', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        const payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkOptionalPayload', 'POST', { credentials: credentials.john.cred, payload });
        const request = { method: 'POST', url: 'http://example.com:8080/hawkOptionalPayload', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional auth', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkOptionalPayload',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'optional', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        let payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkOptionalPayload', 'POST', { credentials: credentials.john.cred, payload });
        payload += 'HACKED';
        const request = { method: 'POST', url: 'http://example.com:8080/hawkOptionalPayload', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(401);
        expect(res.result.message).to.equal('Payload is invalid');
    });

    it('returns an error with payload validation when the payload hash is not included and payload validation is required', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'hawk', { getCredentialsFunc });
        server.route({
            method: 'POST',
            path: '/hawkPayload',
            handler: function (request, h) {

                return 'Success';
            },
            options: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } }
        });

        const payload = 'Here is my payload';
        const authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred });
        const request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.header }, payload };

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(401);
        expect(res.result.message).to.equal('Missing payload authentication');
    });
});
