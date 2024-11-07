'use strict'

// add the user model
const User = require('../../models/user')
const serviceAuth = require('../../services/auth')
const serviceEmail = require('../../services/email')
const crypt = require('../../services/crypt')
const config = require('../../config')
const Need = require('../../models/need')
const axios = require('axios');
const logger = require('../../services/insights');
const jwt = require('jwt-simple')

const login = async (req, res) => {
    try {
        // Log del intento de login
        logger.info('Intento de inicio de sesión', {
            email: req.body.email ? '***@' + req.body.email.split('@')[1] : 'no-email',
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar que existe email
        if (!req.body.email) {
            logger.warn('Intento de login sin email', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Email no proporcionado'
            });
        }

        // Sanitizar email
        const sanitizedEmail = String(req.body.email).toLowerCase().trim();

        // Validar formato de email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(sanitizedEmail)) {
            logger.warn('Intento de login con formato de email inválido', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Formato de email inválido'
            });
        }

        // Generar código de confirmación
        const randomstring = Math.random().toString(36).slice(-12);
        const dateTimeLogin = Date.now();

        // Intentar autenticar usuario
        User.getAuthenticated(sanitizedEmail, async function (err, user, reason) {
            if (err) {
                logger.error('Error en autenticación', {
                    error: err,
                    email: '***@' + sanitizedEmail.split('@')[1],
                    ip: req.ip || req.connection.remoteAddress
                });
                return res.status(500).json({
                    success: false,
                    message: 'Error en la autenticación'
                });
            }

            // Manejar caso de usuario no encontrado o bloqueado
            if (!user) {
                const reasons = User.failedLogin;
                let message = 'Si existe una cuenta asociada, recibirá un correo con el enlace de inicio de sesión.';
                let statusCode = 202;

                switch (reason) {
                    case reasons.NOT_FOUND:
                        logger.info('Intento de login con usuario no encontrado', {
                            email: '***@' + sanitizedEmail.split('@')[1],
                            ip: req.ip || req.connection.remoteAddress
                        });
                        break;

                    case reasons.PASSWORD_INCORRECT:
                        logger.warn('Intento de login con contraseña incorrecta', {
                            email: '***@' + sanitizedEmail.split('@')[1],
                            ip: req.ip || req.connection.remoteAddress
                        });
                        break;

                    case reasons.MAX_ATTEMPTS:
                        message = 'Cuenta temporalmente bloqueada';
                        statusCode = 429;
                        logger.warn('Cuenta bloqueada por máximo de intentos', {
                            email: '***@' + sanitizedEmail.split('@')[1],
                            ip: req.ip || req.connection.remoteAddress
                        });
                        break;

                    case reasons.UNACTIVATED:
                        message = 'Cuenta no activada';
                        logger.warn('Intento de login en cuenta no activada', {
                            email: '***@' + sanitizedEmail.split('@')[1],
                            ip: req.ip || req.connection.remoteAddress
                        });
                        break;

                    case reasons.BLOCKED:
                        message = 'Cuenta bloqueada';
                        logger.warn('Intento de login en cuenta bloqueada', {
                            email: '***@' + sanitizedEmail.split('@')[1],
                            ip: req.ip || req.connection.remoteAddress
                        });
                        break;
                }

                return res.status(statusCode).json({
                    success: false,
                    message
                });
            }

            // Usuario encontrado y válido
            try {
                // Actualizar código de confirmación
                const userUpdated = await User.findByIdAndUpdate(
                    user._id,
                    {
                        confirmationCode: randomstring,
                        dateTimeLogin: dateTimeLogin
                    },
                    { new: true }
                );

                if (!userUpdated) {
                    logger.error('Error actualizando código de confirmación', {
                        userId: user._id,
                        email: '***@' + sanitizedEmail.split('@')[1],
                        ip: req.ip || req.connection.remoteAddress
                    });
                    return res.status(500).json({
                        success: false,
                        message: 'Error actualizando datos de login'
                    });
                }

                // Enviar email de login
                try {
                    await serviceEmail.sendEmailLogin(userUpdated.email, userUpdated.confirmationCode);
                    logger.info('Email de login enviado exitosamente', {
                        userId: user._id,
                        email: '***@' + sanitizedEmail.split('@')[1],
                        ip: req.ip || req.connection.remoteAddress
                    });
                } catch (emailError) {
                    logger.error('Error enviando email de login', {
                        error: emailError,
                        userId: user._id,
                        email: '***@' + sanitizedEmail.split('@')[1],
                        ip: req.ip || req.connection.remoteAddress
                    });
                    return res.status(500).json({
                        success: false,
                        message: 'Error enviando email de login'
                    });
                }

                return res.status(200).json({
                    success: true,
                    message: 'Check email'
                });

            } catch (updateError) {
                logger.error('Error en proceso de login', {
                    error: updateError,
                    userId: user._id,
                    email: '***@' + sanitizedEmail.split('@')[1],
                    ip: req.ip || req.connection.remoteAddress
                });

                return res.status(500).json({
                    success: false,
                    message: 'Error en el proceso de login'
                });
            }
        });

    } catch (error) {
        logger.error('Error general en login', {
            error,
            email: req.body.email ? '***@' + req.body.email.split('@')[1] : 'no-email',
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(500).json({
            success: false,
            message: 'Error en el proceso de login',
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

function getMe(req, res) {
	// Aquí debes verificar la cookie y devolver la info del usuario
	try {
	  // Verificar token de la cookie
	  const token = req.cookies.authToken;
	  if (!token) {
		return res.status(401).json({ message: 'No token provided' });
	  }
  
	  // Verificar y decodificar token
	  console.log('token', token);
	  const decoded = jwt.decode(token, config.SECRET_TOKEN);
	  console.log('decoded', decoded);
	  // Buscar usuario
	  let userId = crypt.decrypt(decoded.sub);
	  User.findById(userId, (err, user) => {
		if (err || !user) {
		  return res.status(401).json({ message: 'Invalid token' });
		}
  
		// Devolver info del usuario
		res.json({
		 sub: crypt.encrypt(user._id.toString()),
		  role: user.role
		  // ... otros campos necesarios
		});
	  });
	} catch (error) {
		console.log('error', error);
	  return res.status(401).json({ message: 'Invalid token' });
	}
  }


const logout = async (req, res) => {
    try {
        res.clearCookie('authToken', {
            httpOnly: true,
            secure: config.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            domain: config.COOKIE_DOMAIN
        });

        res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        logger.error('Error en logout', {
            error,
            ip: req.ip || req.connection.remoteAddress
        });
        res.status(500).json({
            success: false,
            message: 'Error logging out'
        });
    }
};

const checkLogin = async (req, res) => {
    try {
        // Log del intento de verificación de login
        logger.info('Intento de verificación de login', {
            email: req.body.email ? '***@' + req.body.email.split('@')[1] : 'no-email',
            hasConfirmationCode: !!req.body.confirmationCode,
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar campos requeridos
        if (!req.body.email || !req.body.confirmationCode) {
            logger.warn('Verificación de login con campos faltantes', {
                hasEmail: !!req.body.email,
                hasConfirmationCode: !!req.body.confirmationCode,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Email and confirmation code are required'
            });
        }

        // Sanitizar datos
        const sanitizedData = {
            email: String(req.body.email).toLowerCase().trim(),
            confirmationCode: String(req.body.confirmationCode).trim()
        };

        // Validar formato de email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(sanitizedData.email)) {
            logger.warn('Verificación de login con formato de email inválido', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }

        // Buscar usuario
		console.log('sanitizedData', sanitizedData);
        const user = await User.findOne({
            email: sanitizedData.email,
            confirmationCode: sanitizedData.confirmationCode
        });

        // Verificar si se encontró el usuario
        if (!user) {
            logger.warn('Verificación de login fallida - Usuario no encontrado o código inválido', {
                email: '***@' + sanitizedData.email.split('@')[1],
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(401).json({
                success: false,
                message: 'Fail'
            });
        }

        // Verificar tiempo límite
        const limitTime = new Date();
        const timeSpan = 5 * 60 * 1000; // 5 minutos en milisegundos
        limitTime.setTime(limitTime.getTime() - timeSpan);

        if (limitTime.getTime() >= user.dateTimeLogin.getTime()) {
            logger.warn('Verificación de login fallida - Código expirado', {
                userId: user._id,
                email: '***@' + sanitizedData.email.split('@')[1],
                loginTime: user.dateTimeLogin,
                limitTime,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(200).json({
                success: false,
                message: 'Link expired'
            });
        }

        // Generar token
		console.log('user', user);
        const token = serviceAuth.createToken(user);
		// Configurar cookie
       
        // Log de éxito
        logger.info('Login verificado exitosamente', {
            userId: user._id,
            email: '***@' + sanitizedData.email.split('@')[1],
            ip: req.ip || req.connection.remoteAddress
        });

		res.cookie('authToken', token, {
            httpOnly: config.NODE_ENV === 'production',
            secure: config.NODE_ENV === 'production', // true en producción
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000, // 24 horas
            path: '/',
            domain: config.COOKIE_DOMAIN
        });
		console.log('Cookie set:', {
            token: token.substring(0, 20) + '...',
            headers: res.getHeaders()
        });

        // Limpiar código de confirmación después del login exitoso
        await User.findByIdAndUpdate(user._id, {
            confirmationCode: null,
            lastLogin: new Date()
        });

        return res.status(200).json({
            success: true,
            message: 'You have successfully logged in'
        });

    } catch (error) {
        logger.error('Error en verificación de login', {
            error,
            email: req.body.email ? '***@' + req.body.email.split('@')[1] : 'no-email',
            ip: req.ip || req.connection.remoteAddress
        });

        return res.status(500).json({
            success: false,
            message: 'Login verification failed',
            error: config.NODE_ENV === 'production' ? 
                'Internal server error' : 
                error.message
        });
    }
};

const activateUser = async (req, res) => {
    try {
        const encryptedUserId = req.params.userId;

        // Log del intento de activación
        logger.info('Intento de activación de cuenta', {
            encryptedUserId,
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar userId
        if (!encryptedUserId) {
            logger.warn('Intento de activación sin userId', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no válido'
            });
        }

        // Desencriptar userId
        const userId = crypt.decrypt(encryptedUserId);
        
        if (!userId) {
            logger.warn('Fallo en desencriptación de userId', {
                encryptedUserId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no válido'
            });
        }

        // Ejecutar operaciones en paralelo
        const [updatedUser, needsUpdateResult] = await Promise.all([
            // Activar usuario
            User.findByIdAndUpdate(
                userId,
                { 
                    confirmed: true,
                    dateConfirmed: new Date()
                },
                {
                    select: '-createdBy -loginAttempts -confirmationCode',
                    new: true
                }
            ),
            // Reactivar needs
            Need.updateMany(
                { userId: userId },
                { 
                    activated: true,
                    $set: { updatedAt: new Date() }
                }
            )
        ]);

        // Verificar si el usuario existe
        if (!updatedUser) {
            logger.warn('Usuario no encontrado para activación', {
                userId: 'ENCRYPTED',
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Log de éxito de actualización
        logger.info('Usuario y necesidades activadas exitosamente', {
            userId: 'ENCRYPTED',
            email: updatedUser.email ? '***@' + updatedUser.email.split('@')[1] : 'no-email',
            needsUpdated: needsUpdateResult.modifiedCount,
            ip: req.ip || req.connection.remoteAddress
        });

        // Enviar email
        try {
            await serviceEmail.sendMailAccountActivated(updatedUser.email, updatedUser.userName);
            logger.info('Email de activación enviado', {
                userId: 'ENCRYPTED',
                email: '***@' + updatedUser.email.split('@')[1]
            });
        } catch (emailError) {
            logger.error('Error enviando email de activación', {
                error: emailError,
                userId: 'ENCRYPTED',
                email: '***@' + updatedUser.email.split('@')[1]
            });
            // No devolvemos error al cliente ya que la activación fue exitosa
        }

        return res.status(200).json({
            success: true,
            message: 'Usuario activado correctamente',
            data: {
                email: updatedUser.email,
                userName: updatedUser.userName,
                confirmed: updatedUser.confirmed,
                dateConfirmed: updatedUser.dateConfirmed
            }
        });

    } catch (error) {
        logger.error('Error activando usuario', {
            error,
            encryptedUserId: req.params.userId,
            ip: req.ip || req.connection.remoteAddress
        });

        return res.status(500).json({
            success: false,
            message: 'Error al activar el usuario',
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};


//crear metodo para desactivar cuenta
const deactivateUser = async (req, res) => {
    try {
        const encryptedUserId = req.params.userId;

        // Log del intento de desactivación
        logger.info('Intento de desactivación de cuenta', {
            encryptedUserId,
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar userId
        if (!encryptedUserId) {
            logger.warn('Intento de desactivación sin userId', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no válido'
            });
        }

        // Desencriptar userId
        const userId = crypt.decrypt(encryptedUserId);
        
        if (!userId) {
            logger.warn('Fallo en desencriptación de userId', {
                encryptedUserId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no válido'
            });
        }

        // Ejecutar operaciones en paralelo
        const [updatedUser, needsUpdateResult] = await Promise.all([
            // Desactivar usuario
            User.findByIdAndUpdate(
                userId,
                { 
                    confirmed: false,
                    dateDeactivated: new Date()
                },
                {
                    select: '-createdBy -loginAttempts -confirmationCode',
                    new: true
                }
            ),
            // Desactivar needs
            Need.updateMany(
                { userId: userId },
                { 
                    activated: false,
                    $set: { updatedAt: new Date() }
                }
            )
        ]);

        // Verificar si el usuario existe
        if (!updatedUser) {
            logger.warn('Usuario no encontrado para desactivación', {
                userId: 'ENCRYPTED',
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Log de éxito de actualización
        logger.info('Usuario y necesidades desactivadas exitosamente', {
            userId: 'ENCRYPTED',
            email: updatedUser.email ? '***@' + updatedUser.email.split('@')[1] : 'no-email',
            needsUpdated: needsUpdateResult.modifiedCount,
            ip: req.ip || req.connection.remoteAddress
        });

        // Enviar email
        try {
            await serviceEmail.sendMailAccountDeactivated(updatedUser.email, updatedUser.userName);
            logger.info('Email de desactivación enviado', {
                userId: 'ENCRYPTED',
                email: '***@' + updatedUser.email.split('@')[1]
            });
        } catch (emailError) {
            logger.error('Error enviando email de desactivación', {
                error: emailError,
                userId: 'ENCRYPTED',
                email: '***@' + updatedUser.email.split('@')[1]
            });
            // No devolvemos error al cliente ya que la desactivación fue exitosa
        }

        return res.status(200).json({
            success: true,
            message: 'Usuario desactivado correctamente',
            data: {
                email: updatedUser.email,
                userName: updatedUser.userName,
                confirmed: updatedUser.confirmed,
                dateDeactivated: updatedUser.dateDeactivated
            }
        });

    } catch (error) {
        logger.error('Error desactivando usuario', {
            error,
            encryptedUserId: req.params.userId,
            ip: req.ip || req.connection.remoteAddress
        });

        return res.status(500).json({
            success: false,
            message: 'Error al desactivar el usuario',
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

async function verifyCaptcha(token, secretKey) {
	try {
	  const response = await axios.post(
		`https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`
	  );
	  return response.data;
	} catch (error) {
	  console.error('Captcha verification error:', error);
	  return null;
	}
  }

async function signUp(req, res) {

	try {
		// Log del intento de registro
        logger.info('Intento de registro de usuario', {
            email: req.body.email ? '***@' + req.body.email.split('@')[1] : 'no-email',
            ip: req.ip || req.connection.remoteAddress
        });

        // 1. Validar que exista el token del captcha
        if (!req.body.captchaToken) {
            logger.warn('Intento de registro sin captcha', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Token de captcha no proporcionado'
            });
        }


		  // 2. Verificar el captcha
        const captchaResponse = await verifyCaptcha(req.body.captchaToken, config.secretCaptcha);
        if (!captchaResponse || !captchaResponse.success) {
			logger.warn('Verificación de captcha fallida', {
				ip: req.ip || req.connection.remoteAddress,
				score: captchaResponse && captchaResponse.score ? captchaResponse.score : null
			});
            return res.status(400).json({
                success: false,
                message: 'Verificación de captcha fallida'
            });
        }
	 
		// 3. Sanitizar y validar datos de entrada
        const sanitizedData = {
            email: String(req.body.email || '').toLowerCase().trim(),
            userName: String(req.body.userName || '').trim(),
            position: String(req.body.position || '').trim(),
            institution: String(req.body.institution || '').trim(),
            phone: String(req.body.phone || '').trim().replace(/[^\d+]/g, '') // Solo permite números y '+'
        };

        // Validar campos requeridos
        const requiredFields = ['email', 'userName', 'position', 'institution', 'phone'];
        const missingFields = requiredFields.filter(field => !sanitizedData[field]);

        if (missingFields.length > 0) {
            logger.warn('Intento de registro con campos faltantes', {
                missingFields,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Campos requeridos faltantes',
                details: missingFields.reduce((acc, field) => ({
                    ...acc,
                    [field]: `${field} es requerido`
                }), {})
            });
        }
		 // Validar formato de email
		 const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		 if (!emailRegex.test(sanitizedData.email)) {
			 logger.warn('Intento de registro con email inválido', {
				 ip: req.ip || req.connection.remoteAddress
			 });
			 return res.status(400).json({
				 success: false,
				 message: 'Formato de email inválido'
			 });
		 }

		 // Validar formato de teléfono
		 const phoneRegex = /^\+?[\d\s-]{8,}$/;
		 if (!phoneRegex.test(sanitizedData.phone)) {
			 logger.warn('Intento de registro con teléfono inválido', {
				 ip: req.ip || req.connection.remoteAddress
			 });
			 return res.status(400).json({
				 success: false,
				 message: 'Formato de teléfono inválido'
			 });
		 }

		  // 4. Verificar si el usuario existe
		  const existingUser = await User.findOne({ 'email': sanitizedData.email });
		  if (existingUser) {
			  logger.info('Intento de registro con email existente', {
				  email: '***@' + sanitizedData.email.split('@')[1],
				  ip: req.ip || req.connection.remoteAddress
			  });
			  return res.status(202).json({
				  success: true,
				  message: 'Si existe una cuenta asociada, recibirá un correo con más instrucciones.'
			  });
		  }

		   // 5. Crear el nuevo usuario
		   const user = new User({
            ...sanitizedData,
            platform: 'ConectamosValencia',
            dateCreated: new Date()
        });

		// 6. Guardar el usuario
        const userSaved = await user.save();

        // Log de éxito
        logger.info('Usuario registrado exitosamente', {
            userId: userSaved._id,
            email: '***@' + sanitizedData.email.split('@')[1],
            ip: req.ip || req.connection.remoteAddress
        });
		return res.status(200).send({success: true, message: 'Account created' });
		  

	} catch (error) {
		logger.error('Error en registro de usuario', {
            error,
            email: req.body.email ? '***@' + req.body.email.split('@')[1] : 'no-email',
            ip: req.ip || req.connection.remoteAddress
        });

		console.error('Signup error:', error);
		return res.status(500).send({ 
		  message: `Error creating the user: ${error.message}` 
		});
	}
 
	
}

module.exports = {
	login,
	getMe,
	logout,
	checkLogin,
	activateUser,
	deactivateUser,
	signUp
}
