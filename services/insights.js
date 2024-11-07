const config = require('../config');
const appInsights = require('applicationinsights');

const logger = {
    info: (message, meta = {}) => {
        if (config.client_server === 'http://localhost:4200') {
            console.log('AppInsights tracking (INFO):', { message, ...meta });
        } else if (appInsights.defaultClient) {
            appInsights.defaultClient.trackTrace({
                message: typeof message === 'string' ? message : JSON.stringify(message),
                properties: meta,
                severity: appInsights.Contracts.SeverityLevel.Information
            });
        }
    },

    warn: (message, meta = {}) => {
        if (config.client_server === 'http://localhost:4200') {
            console.warn('AppInsights tracking (WARN):', { message, ...meta });
        } else if (appInsights.defaultClient) {
            appInsights.defaultClient.trackTrace({
                message: typeof message === 'string' ? message : JSON.stringify(message),
                properties: meta,
                severity: appInsights.Contracts.SeverityLevel.Warning
            });
        }
    },

    debug: (message, meta = {}) => {
        if (config.client_server === 'http://localhost:4200') {
            console.debug('AppInsights tracking (DEBUG):', { message, ...meta });
        } else if (appInsights.defaultClient) {
            appInsights.defaultClient.trackTrace({
                message: typeof message === 'string' ? message : JSON.stringify(message),
                properties: meta,
                severity: appInsights.Contracts.SeverityLevel.Verbose
            });
        }
    },

    error: (message, meta = {}) => {
        if (config.client_server === 'http://localhost:4200') {
            console.error('AppInsights tracking (ERROR):', { message, ...meta });
        } else if (appInsights.defaultClient) {
            let stringException;
            if (typeof message === 'string') {
                stringException = message;
            } else if (message instanceof Error) {
                stringException = message.message;
                meta.stack = message.stack;
            } else if (typeof message === 'object') {
                stringException = JSON.stringify(message);
            } else {
                stringException = String(message);
            }

            appInsights.defaultClient.trackException({
                exception: new Error(stringException),
                properties: meta
            });
        }
    }
};

module.exports = logger;