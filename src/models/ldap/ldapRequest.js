'use strict';

/**
 * Transforms a raw ldap request into the API-friendly representation of one
 * @module
 */

 var Q = require('q'),
 helpers = require('../../util/helpers'),
 ldapjs = require('ldapjs');

/**
 * Creates the request used during dry run validation
 * @returns {Object}
 */
 function createTestRequest () {
    return {
        requestFrom: '',
        data: 'test'
    };
}

/**
 * Transforms the raw ldap request into a mountebank ldap request
 * @param {Object} request - The raw ldap request
 * @returns {Object} - A promise resolving to the mountebank ldap request
 */
 function createFrom (request) {


// Object.keys(request).forEach(function(obj)
// {
//     console.log('key: '+ obj + ' ==> ' + request[obj]);
// })

    // return Q({
    //     dn: request.dn.toString(),
    //      requestFrom: helpers.socketName(request.socket),
    // });
    switch(request.type)
    {
        case 'BindRequest':
        return Q({
            dn: request.dn.toString(),
            password: request.credentials,
            username: request.name.toString(),
            type: request.type
        });
        break;
        case 'SearchRequest':
        return Q({
            dn: request.baseObject.toString(),
            scope: request.scope,
            filter: request.filter.toString(),
            attributes: request.attributes || '',
            type: request.type
        });
        break;
    }
    return Q({type: request.type});

}

module.exports = {
    createTestRequest: createTestRequest,
    createFrom: createFrom
};
