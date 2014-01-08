// Load modules

var Lab = require('lab');
var Hapi = require('hapi');
var Hawk = require('hawk');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Bewit', function () {

    var credentials = {
        'john': {
            cred: {
                id: 'john',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            }
        },
        'jane': {
            err: Hapi.error.internal('boom')
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

    var getBewit = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.uri.getBewit('http://example.com:8080' + path, { credentials: credentials[id].cred, ttlSec: 60 });
        }
        else {
            return '';
        }
    };

    var bewitHandler = function (request, reply) {

        reply('Success');
    };

    var server = new Hapi.Server();
    before(function (done) {

        server.pack.require('../', function (err) {

            expect(err).to.not.exist;

            server.auth.strategy('default', 'bewit', { getCredentialsFunc: getCredentials })

            server.route([
                { method: 'GET', path: '/bewit', handler: bewitHandler, config: { auth: true } },
                { method: 'GET', path: '/bewitOptional', handler: bewitHandler, config: { auth: { mode: 'optional' } } },
                { method: 'GET', path: '/bewitScope', handler: bewitHandler, config: { auth: { scope: 'x' } } },
                { method: 'GET', path: '/bewitTos', handler: bewitHandler, config: { auth: { tos: '2.0.0' } } }
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

    it('returns an error on insufficient tos', function (done) {

        var bewit = getBewit('john', '/bewitTos');
        server.inject('http://example.com:8080/bewitTos?bewit=' + bewit, function (res) {

            expect(res.statusCode).to.equal(403);
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

        var server = new Hapi.Server();
        server.pack.require('../', function (err) {

            expect(err).to.not.exist;

            server.auth.strategy('default', 'bewit', {
                getCredentialsFunc: getCredentials,
                hawk: {
                    hostHeaderName: 'custom'
                }
            });

            server.route({ method: 'GET', path: '/bewit', handler: bewitHandler, config: { auth: true } });

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('cannot add a route that has payload validation required', function (done) {

        var fn = function () {

            server.route({ method: 'POST', path: '/bewitPayload', handler: bewitHandler, config: { auth: { mode: 'required', payload: 'required' }, payload: { output: 'stream', parse: false } } });
        };

        expect(fn).to.throw(Error);
        done();
    });

    it('cannot add a route that has payload validation as optional', function (done) {

        var fn = function () {

            server.route({ method: 'POST', path: '/bewitPayload', handler: bewitHandler, config: { auth: { mode: 'required', payload: 'optional' }, payload: { output: 'stream', parse: false } } });
        };

        expect(fn).to.throw(Error);
        done();
    });

    it('can add a route that has payload validation as none', function (done) {

        var fn = function () {

            server.route({ method: 'POST', path: '/bewitPayload', handler: bewitHandler, config: { auth: { mode: 'required', payload: false }, payload: { output: 'stream', parse: false } } });
        };

        expect(fn).to.not.throw(Error);
        done();
    });
});
