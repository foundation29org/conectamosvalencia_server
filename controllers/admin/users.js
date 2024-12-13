// functions for each call of the api on admin. Use the user model

'use strict'

// add the user model
const User = require('../../models/user')
const crypt = require('../../services/crypt')
const logger = require('../../services/insights');
const config = require('../../config');

const getAllUsers = async (req, res) => {
    try {
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        // Log del intento de obtención de usuarios
        logger.info('Intento de obtención de todos los usuarios', {
            adminId: crypt.encrypt(adminId),
            ip: req.ip || req.connection.remoteAddress,
            query: req.query
        });

        // Obtener información de usuarios
        const users = await getInfoUser();

        // Log del resultado
        logger.info('Usuarios recuperados exitosamente', {
            adminId: crypt.encrypt(adminId),
            count: users.length,
            ip: req.ip || req.connection.remoteAddress
        });

        return res.status(200).json({
            success: true,
            data: users
        });

    } catch (error) {
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        logger.error('Error obteniendo usuarios', {
            error,
            adminId: crypt.encrypt(adminId),
            ip: req.ip || req.connection.remoteAddress
        });

        return res.status(500).json({
            success: false,
            message: 'Error al obtener usuarios',
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

const getInfoUser = async () => {
    try {
        // Log del inicio de la consulta
        logger.debug('Iniciando consulta de usuarios');

        const users = await User.find(
            { role: { $in: ['User', 'Admin'] } }, 
            'userName institution phone confirmed email role lastLogin'
        );
        
        if (!users || users.length === 0) {
            logger.info('No se encontraron usuarios');
            return [];
        }

        // Log de usuarios encontrados
        logger.debug('Procesando información de usuarios', {
            count: users.length
        });

        const usersInfo = users.map(user => {
            // Sanitizar y validar cada campo
            const sanitizedUser = {
                userId: crypt.encrypt(user._id.toString()),
                userName: String(user.userName || '').trim(),
                email: String(user.email || '').toLowerCase().trim(),
                institution: String(user.institution || '').trim(),
                phone: String(user.phone || '').trim(),
                confirmed: Boolean(user.confirmed),
                role: String(user.role || '').trim(),
                lastLogin: user.lastLogin || null
            };

            // Validar email
            if (sanitizedUser.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedUser.email)) {
                logger.warn('Email inválido encontrado', {
                    userId: crypt.encrypt(user._id),
                    email: '***@invalid'
                });
            }

            // Validar teléfono
            if (sanitizedUser.phone && !/^\+?[\d\s-]{8,}$/.test(sanitizedUser.phone)) {
                logger.warn('Teléfono inválido encontrado', {
                    userId: crypt.encrypt(user._id),
                });
            }

            return sanitizedUser;
        });

        // Log de finalización exitosa
        logger.debug('Información de usuarios procesada exitosamente', {
            count: usersInfo.length
        });

        return usersInfo;

    } catch (error) {
        logger.error('Error en getInfoUser', {
            error
        });
        throw error; // Propagar el error para manejarlo en getAllUsers
    }
};



module.exports = {
	getAllUsers
}
