// Load modules

var Stream = require('stream');
var Lab = require('lab');
var Hapi = require('hapi');
var Hawk = require('hawk');
var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var describe = Lab.experiment;
var it = Lab.test;


describe('Hawk', function () {

    var credentials = {
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

    var getCredentials = function (id, callback) {

        if (credentials[id]) {
            return callback(credentials[id].err, credentials[id].cred);
        }
        else {
            return callback(null, null);
        }
    };

    var hawkHeader = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.client.header('http://example.com:8080' + path, 'POST', { credentials: credentials[id].cred });
        }
        else {
            return '';
        }
    };

    it('returns a reply on successful auth', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawk',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default' } }
            );

            var request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', '/hawk').field } };
            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on failed optional auth', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkOptional',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'optional', strategy: 'default' } } }
            );

            var request = { method: 'POST', url: 'http://example.com:8080/hawkOptional' };
            server.inject(request, function (res) {

                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('includes authorization header in response when the response is a stream', function (done) {

        var hawkStreamHandler = function (request, reply) {

            var TestStream = function () {

                Stream.Readable.call(this);
            };

            Hoek.inherits(TestStream, Stream.Readable);

            TestStream.prototype._read = function (size) {

                var self = this;

                if (this.isDone) {
                    return;
                }
                this.isDone = true;

                setTimeout(function () {

                    self.push('hi');
                }, 2);

                setTimeout(function () {

                    self.push(null);
                }, 5);
            };

            var stream = new TestStream();
            reply(stream);
        };

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkStream', handler: hawkStreamHandler, config: { auth: 'default' } });

            var authHeader = hawkHeader('john', '/hawkStream');
            var request = { method: 'POST', url: 'http://example.com:8080/hawkStream', headers: { authorization: authHeader.field } };
            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['server-authorization']).to.contain('Hawk');

                var options = {
                    payload: res.payload
                };

                getCredentials('john', function (err, cred) {

                    var header = Hawk.server.header(cred, authHeader.artifacts, options);
                    expect(header).to.equal(res.headers['server-authorization']);
                    done();
                });
            });
        });
    });

    it('includes valid authorization header in response when the response is text', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawk',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default'  } }
            );

            var authHeader = hawkHeader('john', '/hawk');
            var request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: authHeader.field } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['server-authorization']).to.contain('Hawk');

                var options = {
                    payload: res.payload,
                    contentType: res.headers['content-type']
                };

                getCredentials('john', function (err, cred) {

                    var header = Hawk.server.header(cred, authHeader.artifacts, options);
                    expect(header).to.equal(res.headers['server-authorization']);

                    done();
                });
            });
        });
    });

    it('includes valid authorization header in response when the request fails validation', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkValidate',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default', validate: { query: {} } } }
            );

            var authHeader = hawkHeader('john', '/hawkValidate?a=1');
            var request = { method: 'POST', url: 'http://example.com:8080/hawkValidate?a=1', headers: { authorization: authHeader.field } };
            server.inject(request, function (res) {

                expect(res.headers['server-authorization']).to.exist;
                expect(res.headers['server-authorization']).to.contain('Hawk');
                expect(res.statusCode).to.equal(400);

                var options = {
                    payload: res.payload,
                    contentType: res.headers['content-type']
                };

                getCredentials('john', function (err, cred) {

                    authHeader.artifacts.credentials = cred;
                    var header = Hawk.server.header(cred, authHeader.artifacts, options);
                    expect(header).to.equal(res.headers['server-authorization']);

                    done();
                });
            });
        });
    });

    it('does not include authorization header in response when the response is an error', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkError',
                handler: function (request, reply) { reply(new Error()); },
                config: { auth: 'default' } }
            );

            var request = { method: 'POST', url: 'http://example.com:8080/hawkError', headers: { authorization: hawkHeader('john', '/hawkError').field } };
            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(500);
                expect(res.headers.authorization).to.not.exist;
                done();
            });
        });
    });

    it('returns an error on bad auth header', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST',
                path: '/hawk',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default' } });

            var request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: hawkHeader('john', 'abcd').field } };
            server.inject(request, function (res) {

                expect(res.result).to.exist;
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('returns an error on bad header format', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawk', handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default' } });

            var request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk' } };
            server.inject(request, function (res) {

                expect(res.result).to.exist;
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('returns an error on bad scheme', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawk', handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default' } });

            var request = { method: 'POST', url: 'http://example.com:8080/hawk', headers: { authorization: 'junk something' } };
            server.inject(request, function (res) {

                expect(res.result).to.exist;
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('returns an error on insufficient tos', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkTos',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { tos: '2.0.0', strategy: 'default' } } });

            var request = { method: 'POST', url: 'http://example.com:8080/hawkTos', headers: { authorization: hawkHeader('john', '/hawkTos').field } };
            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(403);
                done();
            });
        });
    });

    it('returns an error on insufficient scope', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkScope',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { scope: 'x', strategy: 'default'  } }
            });

            var request = { method: 'POST', url: 'http://example.com:8080/hawkScope', payload: 'something', headers: { authorization: hawkHeader('john', '/hawkScope').field } };
            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(403);
                done();
            });
        });
    });

    it('returns a reply on successful auth when using a custom host header key', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

            server.auth.strategy('default', 'hawk', {
                getCredentialsFunc: getCredentials,
                hawk: {
                    hostHeaderName: 'custom'
                }
            });

            server.route({ method: 'POST', path: '/hawk',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: 'default' } }
            );

            var request = { method: 'POST', url: '/hawk', headers: { authorization: hawkHeader('john', '/hawk').field, custom: 'example.com:8080' } };
            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on successful auth and payload validation', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayload',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'application text formatted payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload: payload, contentType: 'text/plain' });
            var request = {
                method: 'POST',
                url: 'http://example.com:8080/hawkPayload',
                headers: { authorization: authHeader.field, 'content-type': 'text/plain' },
                payload: payload,
                simulate: { split: true }
            };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayload',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } } });

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
            payload += 'HACKED';
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Payload is invalid');
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is absent', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayload',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } } });

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
            payload = '';
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Payload is invalid');
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional validation', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayloadOptional',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'optional', strategy: 'default' }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred, payload: payload });
            payload += 'HACKED';
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Payload is invalid');
                done();
            });
        });
    });

    it('returns a reply on successful auth and payload validation when validation is optional', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayloadOptional',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'optional', strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred, payload: payload });
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.result).to.exist;
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on successful auth when payload validation is optional and no payload hash exists', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayloadOptional',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'optional', strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadOptional', 'POST', { credentials: credentials.john.cred });
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadOptional', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.result).to.exist;
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on successful auth and when payload validation is disabled', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayloadNone',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: false, strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadNone', 'POST', { credentials: credentials.john.cred, payload: payload });
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadNone', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on successful auth when the payload is tampered with and the route has disabled validation', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayloadNone',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: false, strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayloadNone', 'POST', { credentials: credentials.john.cred, payload: payload });
            payload += 'HACKED';
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayloadNone', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns a reply on successful auth when auth is optional and when payload validation is required', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkOptionalPayload',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'optional', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkOptionalPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
            var request = { method: 'POST', url: 'http://example.com:8080/hawkOptionalPayload', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload is tampered with and the route has optional auth', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkOptionalPayload',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'optional', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkOptionalPayload', 'POST', { credentials: credentials.john.cred, payload: payload });
            payload += 'HACKED';
            var request = { method: 'POST', url: 'http://example.com:8080/hawkOptionalPayload', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Payload is invalid');
                done();
            });
        });
    });

    it('returns an error with payload validation when the payload hash is not included and payload validation is required', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'hawk', { getCredentialsFunc: getCredentials });
            server.route({ method: 'POST', path: '/hawkPayload',
                handler: function (request, reply) { reply('Success'); },
                config: { auth: { mode: 'required', payload: 'required', strategy: 'default'  }, payload: { override: 'text/plain' } } }
            );

            var payload = 'Here is my payload';
            var authHeader = Hawk.client.header('http://example.com:8080/hawkPayload', 'POST', { credentials: credentials.john.cred });
            var request = { method: 'POST', url: 'http://example.com:8080/hawkPayload', headers: { authorization: authHeader.field }, payload: payload };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Missing payload authentication');
                done();
            });
        });
    });
});
