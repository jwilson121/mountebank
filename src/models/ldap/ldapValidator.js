'use strict';

/**
 * Additional ldap-specific validations
 * @module
 */

var DryRunValidator = require('../dryRunValidator'),
    StubRepository = require('../stubRepository'),
    TcpRequest = require('./ldapRequest'),
    exceptions = require('../../util/errors');

function validateMode (request) {
    var errors = [];
    return errors;
    if (request.mode && ['text', 'binary'].indexOf(request.mode) < 0) {
        errors.push(exceptions.ValidationError("'mode' must be one of ['text', 'binary']"));
    }
    return errors;
}

module.exports = {
    /**
     * Creates the ldap validator, which wraps dry run validation with some protocol-specific validation
     * @param {boolean} allowInjection - The --allowInjection command line parameter
     * @returns {Object}
     */
    create: function (allowInjection) {
        return DryRunValidator.create({
            StubRepository: StubRepository,
            testRequest: TcpRequest.createTestRequest(),
            testProxyResponse: { data: '' },
            allowInjection: allowInjection,
            additionalValidation: validateMode
        });
    }
};
