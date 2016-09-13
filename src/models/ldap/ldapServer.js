'use strict';

/**
 * Represents a ldap imposter
 * @module
 */

var AbstractServer = require('../abstractServer'),
    net = require('net'),
    ldap = require('ldapjs'),
    Q = require('q'),
    winston = require('winston'),
    inherit = require('../../util/inherit'),
    combinators = require('../../util/combinators'),
    helpers = require('../../util/helpers'),
    LdapProxy = require('./ldapProxy'),
    LdapValidator = require('./ldapValidator'),
    ResponseResolver = require('../responseResolver'),
    StubRepository = require('../stubRepository'),
    events = require('events'),
    LdapRequest = require('./ldapRequest');

function createServer (logger, options) {

    function postProcess (response, request) {
        var defaultResponse = options.defaultResponse || {};
        switch(request.type)
        {
            case 'BindRequest':
                return { 
                    authenticate: response.authenticate || defaultResponse.authenticate || ''
                };
                break;
            default:
                return { 
                    authorized: response.authorized || defaultResponse.authorized || '',
                    body: response.body || defaultResponse.body || ''
                };
        }
    }

    var mode = options.mode ? options.mode : 'text',
        encoding = mode === 'binary' ? 'base64' : 'utf8',
        ensureBuffer = function (data) {
            return Buffer.isBuffer(data) ? data : new Buffer(data, encoding);
        },
        proxy = LdapProxy.create(logger, encoding),
        resolver = ResponseResolver.create(proxy, postProcess),
        stubs = StubRepository.create(resolver, options.debug, encoding);
        var result = inherit.from(events.EventEmitter, {
            errorHandler: function (error, container) {
                container.socket.write(JSON.stringify({ errors: [error] }), 'utf8');
            },
            formatRequestShort: function (request) {
                if (request.data.length > 20) {
                    return request.data.toString(encoding).substring(0, 20) + '...';
                }
                else {
                    return request.data.toString(encoding);
                }
            },
            formatRequest: function (ldapRequest) {
                return ldapRequest.data.toString(encoding);
            },
            formatResponse: combinators.identity,
            respond: function (ldapRequest, originalRequest) {
                var clientName = helpers.socketName(originalRequest.socket),
                    scopedLogger = logger.withScope(clientName);

                return stubs.resolve(ldapRequest, scopedLogger).then(function (stubResponse) {
                    var buffer = ensureBuffer(stubResponse.data);

                    if (buffer.length > 0) {
                        originalRequest.socket.write(buffer);
                    }

                    return buffer.toString(encoding);
                });
            },
            metadata: function () { return { mode: mode }; },
            addStub: stubs.addStub,
            stubs: stubs.stubs
        }),
        server = ldap.createServer();

    function isEndOfRequest (requestData) {
        if (!options.endOfRequestResolver || !options.endOfRequestResolver.inject) {
            return true;
        }

        var injected = '(' + options.endOfRequestResolver.inject + ')(requestData, logger)';

        if (mode === 'text') {
            requestData = requestData.toString('utf8');
        }

        try {
            return eval(injected);
        }
        catch (error) {
            logger.error('injection X=> ' + error);
            logger.error('    full source: ' + JSON.stringify(injected));
            logger.error('    requestData: ' + JSON.stringify(requestData));
            return false;
        }
    }

    function standardResponse(req,res,next)
    {
        LdapRequest.createFrom(req).then(function(simpleRequest){
            return stubs.resolve(simpleRequest, logger.withScope("ldap"));
        }).then(function(stubResponse){
            if ( stubResponse.authorized !== 'true')
            {
                return next(new ldap.InsufficientAccessRightsError());
            }
            res.send(stubResponse.body);
            res.end();
            return next();
        });
        return next();
    }
    function bindResponse(req,res,next)
    {
        LdapRequest.createFrom(req).then(function(simpleRequest){
            return stubs.resolve(simpleRequest, logger.withScope("ldap"));
        }).then(function(stubResponse){
            if ( stubResponse.authenticate !== 'true')
            {
                return next(new ldap.InvalidCredentialsError());
            }
            res.end();
            return next();
        })
    }

    var SUFFIX = '';
    server.bind(SUFFIX,bindResponse);
    server.search(SUFFIX, standardResponse);
    server.modify(SUFFIX, standardResponse);
    server.del(SUFFIX, standardResponse);
    server.compare(SUFFIX, standardResponse);
    server.add(SUFFIX, standardResponse);


    // server.on('connection', function (socket) {
    //     var packets = [];
    //     result.emit('connection', socket);

    //     server.bind('cn=*', eventData, function(event) {
    //         /* Act on the event */
    //     });
    //     socket.on('data', function (data) {
    //         packets.push(data);

    //         var requestData = Buffer.concat(packets),
    //             container = { socket: socket, data: requestData.toString(encoding) };

    //         if (isEndOfRequest(requestData)) {
    //             packets = [];
    //             result.emit('request', socket, container);
    //         }
    //     });
    // });

    result.close = function (callback) { server.close(callback); };

    result.listen = function (port) {
        var deferred = Q.defer();
        server.listen(port, function () { deferred.resolve(server.address().port); });
        return deferred.promise;
    };

    return result;
}

/**
 * Initializes the ldap protocol
 * @param {boolean} allowInjection - The --allowInjection command line parameter
 * @param {boolean} recordRequests - The --mock command line parameter
 * @param {boolean} debug - The --debug command line parameter
 * @returns {Object} - The protocol implementation
 */
function initialize (allowInjection, recordRequests, debug) {
    var implementation = {
        protocolName: 'ldap',
        createServer: createServer,
        Request: LdapRequest
    };

    return {
        name: implementation.protocolName,
        create: AbstractServer.implement(implementation, recordRequests, debug, winston).create,
        Validator: { create: combinators.curry(LdapValidator.create, allowInjection) }
    };
}

module.exports = {
    initialize: initialize
};
