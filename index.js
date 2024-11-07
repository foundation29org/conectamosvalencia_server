/*
* MAIN FILE, REQUESTS INFORMATION OF THE CONFIG (CONFIG.JS WHERE TO ESTABLISH IF IT IS DEVELOPMENT OR PROD)
* AND CONFIGURATION WITH EXPRESS (APP.JS), AND ESTABLISH THE CONNECTION WITH THE BD MONGO AND BEGINS TO LISTEN
*/

'use strict'

const config = require('./config')
const mongoose = require('mongoose');
const app = require('./app')
const config = require('./config')
const mongoose = require('mongoose');
const app = require('./app')
let appInsights = require('applicationinsights');

if(config.client_server !== 'http://localhost:4200'){
    appInsights.setup(config.INSIGHTS)
        .setAutoDependencyCorrelation(false)  // Cambiar a false
        .setAutoCollectRequests(true)
        .setAutoCollectPerformance(true)
        .setAutoCollectExceptions(true)
        .setAutoCollectDependencies(false)    // Cambiar a false
        .setAutoCollectConsole(true)
        .setUseDiskRetryCaching(true)
        .setSendLiveMetrics(false)            // Cambiar a false
        .setDistributedTracingMode(appInsights.DistributedTracingModes.AI_AND_W3C) // Cambiar modo
        // Remover estas líneas que causan problemas
        // .setAutoCollectHeartbeat(true)
        // .setInternalLogging(true, true)
        .start();

    // Configuración más simple del cliente
    appInsights.defaultClient.context.tags[appInsights.defaultClient.context.keys.cloudRole] = "api";
    
    // Manejo de errores más simple
    process.on('uncaughtException', (err) => {
        console.error('Uncaught Exception:', err);
        if (appInsights.defaultClient) {
            appInsights.defaultClient.trackException({exception: err});
        }
    });

    process.on('unhandledRejection', (reason) => {
        console.error('Unhandled Rejection:', reason);
        if (appInsights.defaultClient) {
            appInsights.defaultClient.trackException({
                exception: new Error('Unhandled Promise Rejection: ' + reason)
            });
        }
    });
}

mongoose.Promise = global.Promise

app.listen(config.port, () => {
	console.log(`API REST corriendo en http://localhost:${config.port}`)
})
