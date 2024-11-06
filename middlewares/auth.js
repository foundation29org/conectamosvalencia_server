'use strict'

const serviceAuth = require('../services/auth')

function isAuth (roles){

	return async (req, res, next) => {
        try {
			const token = req.cookies.authToken;
			if (!req.headers.authorization){
				return res.status(403).send({ message: 'It does not have authorization'})
			}
	
			serviceAuth.decodeToken(token, roles)
				.then(response => {
					req.user = response
					next()
				})
				.catch(response => {
					//res.status(response.status)
					return res.status(response.status).send({message: response.message})
				})
		} catch (error) {
            logger.error('Error en autenticación', {
                error,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
		
  }


}

module.exports = isAuth
