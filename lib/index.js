'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const Hawk = require('hawk');


// Declare internals

const internals = {};


exports.register = (server, options, next) => {

    server.auth.scheme('hawk', internals.hawk);
    server.auth.scheme('bewit', internals.bewit);
    return next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.hawk = (server, options) => {

    Hoek.assert(options, 'Invalid hawk scheme options');
    Hoek.assert(options.getCredentialsFunc, 'Missing required getCredentialsFunc method in hawk scheme configuration');

    const settings = Hoek.clone(options);
    settings.hawk = settings.hawk || {};

    const scheme = {
        authenticate(request, reply) {

            Hawk.server.authenticate(request.raw.req, settings.getCredentialsFunc, settings.hawk, (err, creds, artifacts) => {

                if (!err) {

                    request.once('peek', (chunk) => {

                        const payloadHash = Hawk.crypto.initializePayloadHash(request.auth.credentials.algorithm, request.headers['content-type']);
                        payloadHash.update(chunk);

                        request.on('peek', (chunk2) => {

                            payloadHash.update(chunk2);
                        });

                        request.once('finish', () => {

                            request.plugins['hapi-auth-hawk'] = { payloadHash: Hawk.crypto.finalizePayloadHash(payloadHash) };
                        });
                    });
                }

                const result = { credentials: creds, artifacts: artifacts };

                if (err) {
                    return reply(err, null, result);
                }

                return reply.continue(result);
            });
        },
        payload(request, reply) {

            if (!request.auth.artifacts.hash) {
                return reply(Boom.unauthorized(null, 'Hawk'));      // Missing
            }

            const plugin = request.plugins['hapi-auth-hawk'];
            if (plugin &&
                Hawk.server.authenticatePayloadHash(plugin.payloadHash, request.auth.artifacts)) {

                return reply.continue();
            }

            return reply(Boom.unauthorized('Payload is invalid'));
        },
        response(request, reply) {

            const response = request.response;
            const payloadHash = Hawk.crypto.initializePayloadHash(request.auth.credentials.algorithm, response.headers['content-type']);

            response.header('trailer', 'server-authorization');
            response.header('transfer-encoding', 'chunked');

            response.on('peek', (chunk) => {

                payloadHash.update(chunk);
            });

            response.once('finish', () => {

                const header = Hawk.server.header(request.auth.credentials, request.auth.artifacts, { hash: Hawk.crypto.finalizePayloadHash(payloadHash) });

                // Trailers set here.
                // hapijs/shot handling of trailers differs from version to version.

                request.raw.res.addTrailers({ 'server-authorization': header });
            });

            return reply.continue();
        }
    };

    return scheme;
};


internals.bewit = (server, options) => {

    Hoek.assert(options, 'Invalid bewit scheme options');
    Hoek.assert(options.getCredentialsFunc, 'Missing required getCredentialsFunc method in bewit scheme configuration');

    const settings = Hoek.clone(options);
    settings.hawk = settings.hawk || {};

    const scheme = {
        authenticate(request, reply) {

            Hawk.server.authenticateBewit(request.raw.req, settings.getCredentialsFunc, settings.hawk, (err, creds, bewit) => {

                const result = { credentials: creds, artifacts: bewit };
                if (err) {
                    return reply(err, null, result);
                }

                return reply.continue(result);
            });
        }
    };

    return scheme;
};
