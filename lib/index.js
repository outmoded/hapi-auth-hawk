// Load modules

var Boom = require('boom');
var Hoek = require('hoek');
var Hawk = require('hawk');


// Declare internals

var internals = {};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('hawk', internals.hawk);
    plugin.auth.scheme('bewit', internals.bewit);
    return next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.hawk = function (server, options) {

    Hoek.assert(options, 'Invalid hawk scheme options');
    Hoek.assert(options.getCredentialsFunc, 'Missing required getCredentialsFunc method in hawk scheme configuration');

    var settings = Hoek.clone(options);
    settings.hawk = settings.hawk || {};

    var scheme = {
        authenticate: function (request, reply) {

            Hawk.server.authenticate(request.raw.req, settings.getCredentialsFunc, settings.hawk, function (err, credentials, artifacts) {

                if (!err) {
                    request.once('peek', function (chunk) {

                        var payloadHash = Hawk.crypto.initializePayloadHash(request.auth.credentials.algorithm, request.headers['content-type']);
                        payloadHash.update(chunk);

                        request.on('peek', function (chunk) {

                            payloadHash.update(chunk);
                        });

                        request.once('finish', function () {

                            request.plugins['hapi-auth-hawk'] = { payloadHash: Hawk.crypto.finalizePayloadHash(payloadHash) };
                        });
                    });
                }

                return reply(err, { credentials: credentials, artifacts: artifacts });
            });
        },
        payload: function (request, next) {

            if (!request.auth.artifacts.hash) {
                return next(false);
            }

            var plugin = request.plugins['hapi-auth-hawk'];
            if (plugin &&
                Hawk.server.authenticatePayloadHash(plugin.payloadHash, request.auth.artifacts)) {

                return next();
            }

            return next(Boom.unauthorized('Payload is invalid'));
        },
        response: function (request, next) {

            var response = request.response;
            var payloadHash = Hawk.crypto.initializePayloadHash(request.auth.credentials.algorithm, response.headers['content-type']);

            response.header('trailer', 'server-authorization');
            response.header('transfer-encoding', 'chunked');

            response.on('peek', function (chunk) {

                payloadHash.update(chunk);
            });

            response.once('finish', function () {

                var header = Hawk.server.header(request.auth.credentials, request.auth.artifacts, { hash: Hawk.crypto.finalizePayloadHash(payloadHash) });
                request.raw.res.addTrailers({ 'server-authorization': header });
            });

            return next();
        }
    };

    return scheme;
};


internals.bewit = function (server, options) {

    Hoek.assert(options, 'Invalid bewit scheme options');
    Hoek.assert(options.getCredentialsFunc, 'Missing required getCredentialsFunc method in bewit scheme configuration');

    var settings = Hoek.clone(options);
    settings.hawk = settings.hawk || {};

    var scheme = {
        authenticate: function (request, reply) {

            Hawk.server.authenticateBewit(request.raw.req, settings.getCredentialsFunc, settings.hawk, function (err, credentials, bewit) {

                return reply(err, { credentials: credentials, artifacts: bewit });
            });
        }
    };

    return scheme;
};
