const Need = require('../models/need');
const crypt = require('../services/crypt')
const User = require('../models/user');
const logger = require('../services/insights');

const createNeed = async (req, res) => {
    try {

        logger.info('Intento de creación de necesidad', {
            userId: req.params.userId,
            ip: req.ip || req.connection.remoteAddress,
            type: req.body.type
        });

        const sanitizedData = {
            type: String(req.body.type || '').trim().toLowerCase(),
            needs: Array.isArray(req.body.needs) ? 
                req.body.needs.map(need => String(need).trim().toLowerCase()) : [],
            otherNeeds: req.body.otherNeeds ? 
                String(req.body.otherNeeds).trim().replace(/[<>]/g, '') : undefined,
            details: req.body.details ? 
                String(req.body.details).trim().replace(/[<>]/g, '') : undefined,
            location: req.body.location ? {
                lat: Number(req.body.location.lat),
                lng: Number(req.body.location.lng)
            } : undefined
        };

        // Log de datos sanitizados
        logger.info('Datos sanitizados', { sanitizedData });

        const userId = req.params.userId;

        // Array para almacenar mensajes de error
        const errors = [];

        // Validar tipo
         // Validar tipo
        if (!sanitizedData.type) {
            errors.push('El tipo es requerido');
        } else if (!['need', 'offer'].includes(sanitizedData.type)) {
            errors.push('El tipo debe ser "need" u "offer"');
        }

        // Validar userId
        if (!userId) {
            errors.push('El ID de usuario es requerido');
        }

         // Validar necesidades
         if (!sanitizedData.needs.length && !sanitizedData.otherNeeds) {
            errors.push('Debe especificar al menos una necesidad o completar otras necesidades');
        }

        // Validar ubicación para necesidades
        if (sanitizedData.type === 'need') {
            if (!sanitizedData.location || !sanitizedData.location.lat || !sanitizedData.location.lng) {
                errors.push('La ubicación es requerida para las necesidades');
            }
        }

        // Si hay errores, retornar respuesta con todos los errores
        if (errors.length > 0) {

            logger.warn('Validación fallida en creación de necesidad', {
                errors,
                userId,
                sanitizedData,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Error de validación',
                errors: errors
            });
        }

        //decrypt userId
        const decryptedUserId = crypt.decrypt(userId);
        // Crear nueva instancia del modelo
        const newNeed = new Need({
            type: sanitizedData.type,
            needs: sanitizedData.needs,
            otherNeeds: sanitizedData.otherNeeds,
            details: sanitizedData.details,
            location: sanitizedData.location,
            timestamp: new Date(),
            userId: decryptedUserId
        });


        // Guardar en la base de datos
        await newNeed.save();

        // Log de éxito
        logger.info('Necesidad creada exitosamente', {
            needId: newNeed._id,
            userId: decryptedUserId,
            type: sanitizedData.type,
            needs: sanitizedData.needs
        });

        // Responder con éxito
        res.status(201).json({
            success: true,
            data: newNeed,
            message: 'Necesidad registrada correctamente'
        });

    } catch (error) {
        // Log detallado del error
        logger.error('Error al crear necesidad', {
            error,
            userId: req.params.userId,
            body: req.body,
            ip: req.ip || req.connection.remoteAddress
        });
        res.status(500).json({
            success: false,
            message: 'Error al procesar la solicitud',
            error: error.message
        });
    }
};

//crea esta funcion api.put('/needs/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.updateNeed)
const updateNeed = async (req, res) => {
    try {
        const needId = req.params.needId;
        const userId = req.params.userId;

        // Log del intento de actualización
        logger.info('Intento de actualización de necesidad', {
            needId,
            userId,
            ip: req.ip || req.connection.remoteAddress,
            body: req.body
        });

        const decryptedUserId = crypt.decrypt(userId);

        // Verificar si la necesidad existe
        const need = await Need.findById(needId);
        if (!need) {
            logger.warn('Intento de actualización de necesidad inexistente', {
                needId,
                userId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        // Verificar permisos
        if (need.userId !== decryptedUserId) {
            logger.warn('Intento de actualización sin permisos', {
                needId,
                userId,
                needUserId: need.userId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(403).json({
                success: false,
                message: 'No tienes permisos para actualizar esta necesidad'
            });
        }

        // Validar los datos de actualización
        //const { type, needs, otherNeeds, details, location } = req.body;
        const sanitizedData = {
            type: req.body.type ? String(req.body.type).trim().toLowerCase() : undefined,
            needs: Array.isArray(req.body.needs) ? 
                req.body.needs.map(need => String(need).trim().toLowerCase()) : undefined,
            otherNeeds: req.body.otherNeeds ? 
                String(req.body.otherNeeds).trim().replace(/[<>]/g, '') : undefined,
            details: req.body.details ? 
                String(req.body.details).trim().replace(/[<>]/g, '') : undefined,
            location: req.body.location ? {
                lat: Number(req.body.location.lat),
                lng: Number(req.body.location.lng)
            } : undefined
        };

        // Log de datos sanitizados
        logger.info('Datos sanitizados para actualización', { 
            needId,
            sanitizedData 
        });

        const errors = [];

         // Validar tipo
        if (sanitizedData.type && !['need', 'offer'].includes(sanitizedData.type)) {
            errors.push('El tipo debe ser "need" u "offer"');
        }


        // Validar necesidades
        if (sanitizedData.needs === undefined && sanitizedData.otherNeeds === undefined) {
            errors.push('Debe especificar al menos una necesidad o completar otras necesidades');
        }

        // Validar ubicación para necesidades
        if (sanitizedData.type === 'need') {
            if (!sanitizedData.location || !sanitizedData.location.lat || !sanitizedData.location.lng) {
                errors.push('La ubicación es requerida para las necesidades');
            }
        }

        // Si hay errores de validación, retornar error
        if (errors.length > 0) {

            logger.warn('Validación fallida en actualización de necesidad', {
                errors,
                needId,
                userId,
                sanitizedData,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Error de validación',
                errors: errors
            });
        }

         // Eliminar propiedades undefined antes de actualizar
         Object.keys(sanitizedData).forEach(key => 
            sanitizedData[key] === undefined && delete sanitizedData[key]
        );

        // Actualizar la necesidad con datos sanitizados
        const updatedNeed = await Need.findByIdAndUpdate(
            needId, 
            {
                ...sanitizedData,
                timestamp: new Date()
            }, 
            { 
                new: true,
                runValidators: true
            }
        );

        // Log de éxito
        logger.info('Necesidad actualizada exitosamente', {
            needId,
            userId: decryptedUserId,
            updates: sanitizedData
        });
        res.status(200).json({
            success: true,
            data: updatedNeed,
            message: 'Necesidad actualizada correctamente'
        });
    } catch (error) {
        // Log detallado del error
        logger.error('Error al actualizar necesidad', {
            error,
            needId: req.params.needId,
            userId: req.params.userId,
            body: req.body,
            ip: req.ip || req.connection.remoteAddress
        });
        res.status(500).json({
            success: false,
            message: 'Error al actualizar la necesidad',
            error: error.message
        });
    }
}

const getAllNeedsComplete = async (req, res) => {
    try {
         // Log de intento de obtención
         logger.info('Intento de obtención de todas las necesidades', {
            ip: req.ip || req.connection.remoteAddress,
            query: req.query, // Por si añadimos filtros en el futuro
            userId: req.params.userId
        });
        // Sanitizar parámetros de consulta si los hubiera
        const sanitizedQuery = {
            activated: true,
            // Aquí podrían ir más filtros sanitizados si se añaden en el futuro
        };

        // Log de parámetros sanitizados
        logger.info('Parámetros de búsqueda sanitizados', {
            sanitizedQuery,
            ip: req.ip || req.connection.remoteAddress
        });
        // Puedes añadir .sort({ timestamp: -1 }) si quieres ordenar por fecha descendente
        // Obtener todas las necesidades con los filtros
        const needs = await Need.find(sanitizedQuery);

       // Validar el resultado
        if (!needs || needs.length === 0) {
            logger.info('No se encontraron necesidades', {
                sanitizedQuery,
                ip: req.ip || req.connection.remoteAddress
            });
        } else {
            logger.info('Necesidades recuperadas exitosamente', {
                count: needs.length,
                ip: req.ip || req.connection.remoteAddress
            });
        }

        // Sanitizar datos sensibles antes de enviar (si es necesario)
        const sanitizedNeeds = needs.map(need => ({
            ...need.toObject(),
            // Aquí podrías eliminar o modificar campos sensibles si los hubiera
        }));

        res.status(200).json({
            success: true,
            data: sanitizedNeeds,
            count: needs.length
        });

    } catch (error) {
        // Log detallado del error
        logger.error('Error al obtener necesidades', {
            error,
            ip: req.ip || req.connection.remoteAddress,
            query: req.query
        });

        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

//crea esta funcion api.get('/needsuser/complete/:userId', corsWithOptions, auth(roles.AllLessResearcher), needsCtrl.getAllNeedsCompleteForUser)
const getAllNeedsCompleteForUser = async (req, res) => {
    try {
        const { userId } = req.params;

        // Log de intento de obtención
        logger.info('Intento de obtención de necesidades de usuario', {
            userId,
            ip: req.ip || req.connection.remoteAddress,
            query: req.query
        });

        // Validar userId
        if (!userId) {
            logger.warn('Intento de obtención sin userId', {
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no proporcionado'
            });
        }

        // Decrypt userId
        const decryptedUserId = crypt.decrypt(userId);

        // Sanitizar parámetros de consulta
        const sanitizedQuery = {
            userId: decryptedUserId,
            activated: true
        };

        // Log de parámetros sanitizados
        logger.info('Parámetros de búsqueda sanitizados', {
            sanitizedQuery: { ...sanitizedQuery, userId: 'ENCRYPTED' }, // No logear el userId descifrado
            ip: req.ip || req.connection.remoteAddress
        });

        // Obtener necesidades del usuario
        const needs = await Need.find(sanitizedQuery);

        // Validar el resultado
        if (!needs || needs.length === 0) {
            logger.info('No se encontraron necesidades para el usuario', {
                userId: 'ENCRYPTED', // No logear el userId descifrado
                ip: req.ip || req.connection.remoteAddress
            });
        } else {
            logger.info('Necesidades de usuario recuperadas exitosamente', {
                userId: 'ENCRYPTED', // No logear el userId descifrado
                count: needs.length,
                ip: req.ip || req.connection.remoteAddress
            });
        }

        // Sanitizar datos sensibles antes de enviar
        const sanitizedNeeds = needs.map(need => ({
            ...need.toObject(),
            userId: userId // Devolver el userId encriptado
        }));

        res.status(200).json({
            success: true,
            data: sanitizedNeeds,
            count: needs.length
        });

    } catch (error) {
        // Log detallado del error
        logger.error('Error al obtener necesidades del usuario', {
            error,
            userId: req.params.userId, // Usar el userId encriptado
            ip: req.ip || req.connection.remoteAddress,
            query: req.query
        });

        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

const getAllNeedsForHeatmap = async (req, res) => {
    try {
        // Log de intento de obtención
        logger.info('Intento de obtención de necesidades para heatmap', {
            ip: req.ip || req.connection.remoteAddress,
            query: req.query
        });

        // Sanitizar parámetros de consulta
        const sanitizedQuery = {
            activated: true,
            // Aquí podrían ir más filtros si se necesitan en el futuro
        };

        // Log de parámetros de búsqueda
        logger.info('Parámetros de búsqueda sanitizados para heatmap', {
            sanitizedQuery,
            ip: req.ip || req.connection.remoteAddress
        });

        // Obtener necesidades
        const needs = await Need.find(sanitizedQuery);

        // Validar el resultado
        if (!needs || needs.length === 0) {
            logger.info('No se encontraron necesidades para el heatmap', {
                sanitizedQuery,
                ip: req.ip || req.connection.remoteAddress
            });
        } else {
            logger.info('Necesidades para heatmap recuperadas exitosamente', {
                count: needs.length,
                ip: req.ip || req.connection.remoteAddress
            });
        }
        
        // Sanitizar los datos antes de enviarlos
        const sanitizedNeeds = needs.map(need => ({
            type: String(need.type || '').trim().toLowerCase(),
            needs: Array.isArray(need.needs) ? 
                need.needs.map(n => String(n).trim().toLowerCase()) : [],
            location: need.location ? {
                lat: Number(need.location.lat),
                lng: Number(need.location.lng)
            } : null,
            timestamp: need.timestamp,
            _id: need._id,
            status: String(need.status || '').trim(),
            // Ocultar datos sensibles
            otherNeeds: need.otherNeeds ? '[Contenido privado]' : '',
            details: need.details ? '[Contenido privado]' : ''
        }));

        // Log de éxito con métricas
        logger.info('Datos del heatmap procesados', {
            totalNeeds: needs.length,
            needsWithLocation: sanitizedNeeds.filter(n => n.location).length,
            types: [...new Set(sanitizedNeeds.map(n => n.type))],
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(200).json({
            success: true,
            data: sanitizedNeeds,
            count: needs.length
        });

    } catch (error) {
        // Log detallado del error
        logger.error('Error al obtener necesidades para heatmap', {
            error,
            ip: req.ip || req.connection.remoteAddress,
            query: req.query
        });

        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

const deleteNeed = async (req, res) => {
    try {
        const needId = req.params.needId;
        const userId = req.params.userId;

        // Log del intento de eliminación
        logger.info('Intento de eliminación de necesidad', {
            needId,
            userId,
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar parámetros
        if (!needId) {
            logger.warn('Intento de eliminación sin needId', {
                userId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad no proporcionado'
            });
        }

        if (!userId) {
            logger.warn('Intento de eliminación sin userId', {
                needId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no proporcionado'
            });
        }

        // Desencriptar userId
        const decryptedUserId = crypt.decrypt(userId);

        // Buscar la necesidad
        const need = await Need.findById(needId);

        // Verificar si la necesidad existe
        if (!need) {
            logger.warn('Intento de eliminación de necesidad inexistente', {
                needId,
                userId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        // Verificar permisos
        if (need.userId !== decryptedUserId) {
            logger.warn('Intento de eliminación sin permisos', {
                needId,
                userId,
                needUserId: 'ENCRYPTED', // No logear el userId real
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(403).json({
                success: false,
                message: 'No tienes permisos para eliminar esta necesidad'
            });
        }

        // Eliminar la necesidad
        const deletedNeed = await Need.findByIdAndRemove(needId);

        // Log de éxito
        logger.info('Necesidad eliminada exitosamente', {
            needId,
            userId: 'ENCRYPTED', // No logear el userId descifrado
            type: deletedNeed.type,
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(200).json({
            success: true,
            message: 'Necesidad eliminada correctamente'
        });

    } catch (error) {
        // Log detallado del error
        logger.error('Error al eliminar necesidad', {
            error,
            needId: req.params.needId,
            userId: req.params.userId, // Usar el userId encriptado
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(500).json({
            success: false,
            message: 'Error al eliminar la necesidad',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

const superadminDeleteNeed = async (req, res) => {
    try {
        const needId = req.params.needId;
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';

        // Log del intento de eliminación por superadmin
        logger.info('Intento de eliminación por superadmin', {
            needId,
            adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar needId
        if (!needId) {
            logger.warn('Intento de eliminación superadmin sin needId', {
                adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad no proporcionado'
            });
        }

        // Buscar la necesidad antes de eliminar para logging
        const need = await Need.findById(needId);

        if (!need) {
            logger.warn('Intento de eliminación superadmin de necesidad inexistente', {
                needId,
                adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        // Guardar información relevante antes de eliminar
        const needInfo = {
            type: need.type,
            userId: 'ENCRYPTED', // No logear el userId real
            createdAt: need.timestamp
        };

        // Eliminar la necesidad
        const deletedNeed = await Need.findByIdAndRemove(needId);

        // Log de éxito
        logger.info('Necesidad eliminada exitosamente por superadmin', {
            needId,
            adminId,
            needInfo,
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(200).json({
            success: true,
            message: 'Necesidad eliminada correctamente por superadmin'
        });

    } catch (error) {
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        // Log detallado del error
        logger.error('Error en eliminación superadmin', {
            error,
            needId: req.params.needId,
            adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(500).json({
            success: false,
            message: 'Error al eliminar la necesidad',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

//crea esta funcion api.get('/needs/phone/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.getAllNeedsForPhone)
const getPhone = async (req, res) => {
    try {
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        const needId = req.params.needId;

        // Log del intento de obtención de teléfono
        logger.info('Intento de obtención de teléfono', {
            needId,
            requestingUserId: adminId, // Usuario que solicita (admin/superadmin)
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar needId
        if (!needId) {
            logger.warn('Intento de obtención de teléfono sin needId', {
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad no proporcionado'
            });
        }

        // Buscar la necesidad
        const need = await Need.findOne({ 
            _id: needId,
            activated: true
        });

        // Verificar si la necesidad existe
        if (!need) {
            logger.warn('Intento de obtención de teléfono de necesidad inexistente', {
                needId,
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        // Buscar el usuario
        const user = await User.findById(need.userId);

        // Verificar si el usuario existe
        if (!user) {
            logger.warn('Usuario no encontrado para necesidad', {
                needId,
                userId: 'ENCRYPTED',
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Verificar si el usuario tiene teléfono
        if (!user.phone) {
            logger.info('Usuario sin teléfono registrado', {
                needId,
                userId: 'ENCRYPTED',
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Usuario sin teléfono registrado'
            });
        }

        // Log de éxito
        logger.info('Teléfono obtenido exitosamente', {
            needId,
            requestingUserId: adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        // Sanitizar y devolver el teléfono
        const sanitizedPhone = String(user.phone).trim();
        
        res.status(200).json({
            success: true,
            data: sanitizedPhone
        });

    } catch (error) {
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        // Log detallado del error
        logger.error('Error al obtener teléfono', {
            error,
            needId: req.params.needId,
            requestingUserId: adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(500).json({
            success: false,
            message: 'Error al obtener el teléfono',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

//change status
const updateStatus = async (req, res) => {
    try {
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        const needId = req.params.needId;
        const { status } = req.body;

        // Log del intento de actualización de estado
        logger.info('Intento de actualización de estado', {
            needId,
            newStatus: status,
            requestingUserId: adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        // Validar needId
        if (!needId) {
            logger.warn('Intento de actualización de estado sin needId', {
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad no proporcionado'
            });
        }

        // Validar status
        if (!status) {
            logger.warn('Intento de actualización sin estado', {
                needId,
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Estado no proporcionado'
            });
        }

        // Sanitizar el estado
        const sanitizedStatus = String(status).trim().toLowerCase();

        // Validar que el estado sea válido
        const validStatuses = ['pending', 'in_progress', 'completed', 'cancelled'];
        if (!validStatuses.includes(sanitizedStatus)) {
            logger.warn('Intento de actualización con estado inválido', {
                needId,
                invalidStatus: sanitizedStatus,
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(400).json({
                success: false,
                message: 'Estado inválido',
                validStatuses
            });
        }

        // Buscar la necesidad antes de actualizar
        const existingNeed = await Need.findById(needId);

        if (!existingNeed) {
            logger.warn('Intento de actualización de estado en necesidad inexistente', {
                needId,
                requestingUserId: adminId,
                ip: req.ip || req.connection.remoteAddress
            });
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        // Actualizar el estado
        const updatedNeed = await Need.findByIdAndUpdate(
            needId, 
            { 
                status: sanitizedStatus,
                lastUpdated: new Date()
            }, 
            { 
                new: true,
                runValidators: true 
            }
        );

        // Log de éxito
        logger.info('Estado actualizado exitosamente', {
            needId,
            oldStatus: existingNeed.status,
            newStatus: sanitizedStatus,
            requestingUserId: adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(200).json({
            success: true,
            data: updatedNeed,
            message: 'Estado actualizado correctamente'
        });

    } catch (error) {
        // Log detallado del error
        const adminId = req.user && req.user.id ? req.user.id : 'unknown';
        logger.error('Error al actualizar estado', {
            error,
            needId: req.params.needId,
            status: req.body.status,
            requestingUserId: adminId,
            ip: req.ip || req.connection.remoteAddress
        });

        res.status(500).json({
            success: false,
            message: 'Error al actualizar el estado de la necesidad',
            error: process.env.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

module.exports = {
    createNeed,
    updateNeed,
    getAllNeedsComplete,
    getAllNeedsForHeatmap,
    getAllNeedsCompleteForUser,
    deleteNeed,
    superadminDeleteNeed,
    getPhone,
    updateStatus
}; 