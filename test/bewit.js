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
        john: {
            cred: {
                id: 'john',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            }
        },
        jane: {
            err: Boom.internal('boom')
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

    const getBewit = function (id, path) {

        if (credentials[id] && credentials[id].cred) {
            return Hawk.uri.getBewit('http://example.com:8080' + path, { credentials: credentials[id].cred, ttlSec: 60 });
        }
        return '';
    };

    const bewitHandler = function (request, h) {

        return 'Success';
    };

    let server = Hapi.server();

    before(async () => {

        await server.register(require('../'));

        server.auth.strategy('default', 'bewit', { getCredentialsFunc });

        server.route([
            { method: 'GET', path: '/bewit', handler: bewitHandler, options: { auth: 'default' } },
            { method: 'GET', path: '/bewitOptional', handler: bewitHandler, options: { auth: { mode: 'optional', strategy: 'default' } } },
            { method: 'GET', path: '/bewitScope', handler: bewitHandler, options: { auth: { scope: 'x', strategy: 'default' } } }
        ]);
    });

    it('returns a reply on successful auth', async () => {

        const bewit = getBewit('john', '/bewit');
        const res = await server.inject('http://example.com:8080/bewit?bewit=' + bewit);

        expect(res.result).to.equal('Success');
    });

    it('returns an error reply on failed optional auth', async () => {

        const bewit = getBewit('john', '/abc');
        const res = await server.inject('http://example.com:8080/bewitOptional?bewit=' + bewit);

        expect(res.statusCode).to.equal(401);
    });

    it('returns an error on bad bewit', async () => {

        const bewit = getBewit('john', '/abc');
        const res = await server.inject('http://example.com:8080/bewit?bewit=' + bewit);

        expect(res.statusCode).to.equal(401);
    });

    it('returns an error on bad bewit format', async () => {

        const res = await server.inject('http://example.com:8080/bewit?bewit=junk');

        expect(res.statusCode).to.equal(400);
    });

    it('returns an error on insufficient scope', async () => {

        const bewit = getBewit('john', '/bewitScope');
        const res = await server.inject('http://example.com:8080/bewitScope?bewit=' + bewit);

        expect(res.statusCode).to.equal(403);
    });

    it('returns a reply on successful auth when using a custom host header key', async () => {

        const bewit = getBewit('john', '/bewit');
        const request = { method: 'GET', url: '/bewit?bewit=' + bewit, headers: { custom: 'example.com:8080' } };

        server = new Hapi.Server();
        await server.register(require('../'));

        server.auth.strategy('default', 'bewit', {
            getCredentialsFunc,
            hawk: {
                hostHeaderName: 'custom'
            }
        });

        server.route({ method: 'GET', path: '/bewit', handler: bewitHandler, options: { auth: 'default' } });

        const res = await server.inject(request);

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('Success');
    });

    it('cannot add a route that has payload validation required', () => {

        const fn = function () {

            server.route({ method: 'POST',
                path: '/bewitPayload',
                handler: bewitHandler,
                options: { auth: { mode: 'required', strategy: 'default', payload: 'required' },
                    payload: { output: 'stream', parse: false } }
            });
        };

        expect(fn).to.throw('Payload validation can only be required when all strategies support it in /bewitPayload');
    });

    it('cannot add a route that has payload validation as optional', () => {

        const fn = function () {

            server.route({ method: 'POST',
                path: '/bewitPayload',
                handler: bewitHandler,
                options: { auth: { mode: 'required', strategy: 'default', payload: 'optional' },
                    payload: { output: 'stream', parse: false } }
            });
        };

        expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in /bewitPayload');
    });

    it('can add a route that has payload validation as none', () => {

        const fn = function () {

            server.route({ method: 'POST',
                path: '/bewitPayload',
                handler: bewitHandler,
                options: { auth: { mode: 'required', strategy: 'default', payload: false },
                    payload: { output: 'stream', parse: false } }
            });
        };

        expect(fn).to.not.throw();
    });
});
