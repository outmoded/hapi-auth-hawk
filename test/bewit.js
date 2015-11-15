'use strict';

// Load modules

const Boom = require('boom');
const Code = require('code');
const Hapi = require('hapi');
const Hawk = require('hawk');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const before = lab.before;
const expect = Code.expect;


describe('bewit scheme', () => {

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
        }
    };

    const getCredentials = function (id, callback) {

        if (credentials[id]) {
            return callback(credentials[id].err, credentials[id].cred);
        }
        return callback(null, null);
    };

    const getBewit = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.uri.getBewit('http://example.com:8080' + path, { credentials: credentials[id].cred, ttlSec: 60 });
        }
        return '';
    };

    const bewitHandler = function (request, reply) {

        reply('Success');
    };

    let server = new Hapi.Server();
    server.connection();
    before((done) => {

        server.register(require('../'), (err) => {

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

    it('returns a reply on successful auth', (done) => {

        const bewit = getBewit('john', '/bewit');
        server.inject('http://example.com:8080/bewit?bewit=' + bewit, (res) => {

            expect(res.result).to.equal('Success');
            done();
        });
    });

    it('returns an error reply on failed optional auth', (done) => {

        const bewit = getBewit('john', '/abc');
        server.inject('http://example.com:8080/bewitOptional?bewit=' + bewit, (res) => {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns an error on bad bewit', (done) => {

        const bewit = getBewit('john', '/abc');
        server.inject('http://example.com:8080/bewit?bewit=' + bewit, (res) => {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns an error on bad bewit format', (done) => {

        server.inject('http://example.com:8080/bewit?bewit=junk', (res) => {

            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('returns an error on insufficient scope', (done) => {

        const bewit = getBewit('john', '/bewitScope');
        server.inject('http://example.com:8080/bewitScope?bewit=' + bewit, (res) => {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('returns a reply on successful auth when using a custom host header key', (done) => {

        const bewit = getBewit('john', '/bewit');
        const request = { method: 'GET', url: '/bewit?bewit=' + bewit, headers: { custom: 'example.com:8080' } };

        server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bewit', {
                getCredentialsFunc: getCredentials,
                hawk: {
                    hostHeaderName: 'custom'
                }
            });

            server.route({ method: 'GET', path: '/bewit', handler: bewitHandler, config: { auth: 'default' } });

            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('Success');
                done();
            });
        });
    });

    it('cannot add a route that has payload validation required', (done) => {

        const fn = function () {

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

    it('cannot add a route that has payload validation as optional', (done) => {

        const fn = function () {

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

    it('can add a route that has payload validation as none', (done) => {

        const fn = function () {

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
