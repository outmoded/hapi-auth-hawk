// Load modules

var Boom = require('boom');
var Code = require('code');
var Hapi = require('hapi');
var Hawk = require('hawk');
var Lab = require('lab');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.describe;
var it = lab.it;
var before = lab.before;
var expect = Code.expect;


describe('bewit scheme', function () {

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
        }
    };

    var getCredentials = function (id, callback) {

        if (credentials[id]) {
            return callback(credentials[id].err, credentials[id].cred);
        }
        return callback(null, null);
    };

    var getBewit = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.uri.getBewit('http://example.com:8080' + path, { credentials: credentials[id].cred, ttlSec: 60 });
        }
        return '';
    };

    var bewitHandler = function (request, reply) {

        reply('Success');
    };

    var server = new Hapi.Server();
    server.connection();
    before(function (done) {

        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bewit', true, { getCredentialsFunc: getCredentials });

            server.route([
                { method: 'GET', path: '/bewit', handler: bewitHandler, config: { auth: 'default' } },
                { method: 'GET', path: '/bewitOptional', handler: bewitHandler, config: { auth: { mode: 'optional', strategy: 'default' } } },
                { method: 'GET', path: '/bewitScope', handler: bewitHandler, config: { auth: { scope: 'x', strategy: 'default' } } }
            ]);

            done();
        });
    });

    it('returns a reply on successful auth', function (done) {

        var bewit = getBewit('john', '/bewit');
        server.inject('http://example.com:8080/bewit?bewit=' + bewit, function (res) {

            expect(res.result).to.equal('Success');
            done();
        });
    });

    it('returns an error reply on failed optional auth', function (done) {

        var bewit = getBewit('john', '/abc');
        server.inject('http://example.com:8080/bewitOptional?bewit=' + bewit, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns an error on bad bewit', function (done) {

        var bewit = getBewit('john', '/abc');
        server.inject('http://example.com:8080/bewit?bewit=' + bewit, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns an error on bad bewit format', function (done) {

        server.inject('http://example.com:8080/bewit?bewit=junk', function (res) {

            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('returns an error on insufficient scope', function (done) {

        var bewit = getBewit('john', '/bewitScope');
        server.inject('http://example.com:8080/bewitScope?bewit=' + bewit, function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('returns a reply on successful auth when using a custom host header key', function (done) {

        var bewit = getBewit('john', '/bewit');
        var request = { method: 'GET', url: '/bewit?bewit=' + bewit, headers: { custom: 'example.com:8080' } };

        server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bewit', {
                getCredentialsFunc: getCredentials,
                hawk: {
                    hostHeaderName: 'custom'
                }
            });

            server.route({ method: 'GET', path: '/bewit', handler: bewitHandler, config: { auth: 'default' } });

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('cannot add a route that has payload validation required', function (done) {

        var fn = function () {

            server.route({ method: 'POST',
                path: '/bewitPayload',
                handler: bewitHandler,
                config: { auth: { mode: 'required', strategy: 'default', payload: 'required' },
                    payload: { output: 'stream', parse: false } }
            });
        };

        expect(fn).to.throw('Payload validation can only be required when all strategies support it in path: /bewitPayload');
        done();
    });

    it('cannot add a route that has payload validation as optional', function (done) {

        var fn = function () {

            server.route({ method: 'POST',
                path: '/bewitPayload',
                handler: bewitHandler,
                config: { auth: { mode: 'required', strategy: 'default', payload: 'optional' },
                    payload: { output: 'stream', parse: false } }
            });
        };

        expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in path: /bewitPayload');
        done();
    });

    it('can add a route that has payload validation as none', function (done) {

        var fn = function () {

            server.route({ method: 'POST',
                path: '/bewitPayload',
                handler: bewitHandler,
                config: { auth: { mode: 'required', strategy: 'default', payload: false },
                    payload: { output: 'stream', parse: false } }
            });
        };

        expect(fn).to.not.throw();
        done();
    });
});
