'use strict'

const serviceAuth = require('../services/auth')
const logger = require('../services/insights');

function isAuth(roles) {
    return async (req, res, next) => {
        try {
            // Obtener token de la cookie en lugar del header
            const token = req.cookies.cv_auth_token;
            
            if (!token) {
                logger.warn('Intento de acceso sin token', {
                    ip: req.ip || req.connection.remoteAddress,
                    path: req.path
                });
                return res.status(403).send({ message: 'It does not have authorization' });
            }

            // Log del token recibido
            logger.debug('Token recibido', {
                tokenLength: token.length,
                path: req.path
            });
    
            serviceAuth.decodeToken(token, roles)
                .then(response => {
                    req.user = response;
                    next();
                })
                .catch(response => {
                    logger.warn('Token inválido o sin permisos', {
                        error: response,
                        path: req.path
                    });
                    return res.status(response.status).send({message: response.message});
                });
        } catch (error) {
            logger.error('Error en autenticación', {
                error,
                ip: req.ip || req.connection.remoteAddress,
                path: req.path
            });
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
    };
}

module.exports = isAuth
