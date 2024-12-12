const Need = require('../models/need');
const crypt = require('../services/crypt')
const User = require('../models/user');
const logger = require('../services/insights');
const config = require('../config');


const isValidPhone = (phone) => {
    // Eliminar espacios y guiones para la validación
    const cleanPhone = phone.replace(/[\s-]/g, '');
    return /^[+]?[0-9]{9,15}$/.test(cleanPhone);
};

const createNeed = async (req, res) => {
    try {
        logger.info('Intento de creación de necesidad', {
            userId: req.params.userId,
            ip: req.ip || req.connection.remoteAddress,
        });

        const sanitizedData = {
            personalInfo: {
                fullName: String(req.body.personalInfo?.fullName || '').trim(),
                idType: String(req.body.personalInfo?.idType || '').trim(),
                idNumber: String(req.body.personalInfo?.idNumber || '').trim(),
                lostDocumentation: Boolean(req.body.personalInfo?.lostDocumentation),
                birthDate: new Date(req.body.personalInfo?.birthDate),
                gender: String(req.body.personalInfo?.gender || '').trim(),
                language: String(req.body.personalInfo?.language || '').trim(),
                residence: String(req.body.personalInfo?.residence || '').trim(),
                city: String(req.body.personalInfo?.city || '').trim(),
                householdMembers: Number(req.body.personalInfo?.householdMembers),
                phone: String(req.body.personalInfo?.phone || '').replace(/[\s-]/g, '').trim()
            },
            housing: {
                items: {
                    noHousing: Boolean(req.body.housing?.items?.noHousing),
                    housingDeficiencies: Boolean(req.body.housing?.items?.housingDeficiencies),
                    unsanitary: Boolean(req.body.housing?.items?.unsanitary),
                    overcrowding: Boolean(req.body.housing?.items?.overcrowding),
                    noBasicGoods: Boolean(req.body.housing?.items?.noBasicGoods),
                    foodShortage: Boolean(req.body.housing?.items?.foodShortage)
                },
                observations: String(req.body.housing?.observations || '').trim()
            },
            employment: {
                items: {
                    allUnemployed: Boolean(req.body.employment?.items?.allUnemployed),
                    jobLoss: Boolean(req.body.employment?.items?.jobLoss),
                    temporaryLayoff: Boolean(req.body.employment?.items?.temporaryLayoff),
                    precariousEmployment: Boolean(req.body.employment?.items?.precariousEmployment)
                },
                observations: String(req.body.employment?.observations || '').trim()
            },
            socialNetworks: {
                items: {
                    socialIsolation: Boolean(req.body.socialNetworks?.items?.socialIsolation),
                    neighborConflicts: Boolean(req.body.socialNetworks?.items?.neighborConflicts),
                    needsInstitutionalSupport: Boolean(req.body.socialNetworks?.items?.needsInstitutionalSupport),
                    vulnerableMinors: Boolean(req.body.socialNetworks?.items?.vulnerableMinors)
                },
                observations: String(req.body.socialNetworks?.observations || '').trim()
            },
            publicServices: {
                items: {
                    noHealthCoverage: Boolean(req.body.publicServices?.items?.noHealthCoverage),
                    discontinuedMedicalTreatment: Boolean(req.body.publicServices?.items?.discontinuedMedicalTreatment),
                    unschooledMinors: Boolean(req.body.publicServices?.items?.unschooledMinors),
                    dependencyWithoutAssessment: Boolean(req.body.publicServices?.items?.dependencyWithoutAssessment),
                    mentalHealthIssues: Boolean(req.body.publicServices?.items?.mentalHealthIssues)
                },
                observations: String(req.body.publicServices?.observations || '').trim()
            },
            socialParticipation: {
                items: {
                    memberOfOrganizations: Boolean(req.body.socialParticipation?.items?.memberOfOrganizations),
                    receivesSocialServices: Boolean(req.body.socialParticipation?.items?.receivesSocialServices)
                },
                observations: String(req.body.socialParticipation?.observations || '').trim()
            },
            economicCoverage: {
                items: {
                    noIncome: Boolean(req.body.economicCoverage?.items?.noIncome),
                    pensionsOrBenefits: Boolean(req.body.economicCoverage?.items?.pensionsOrBenefits),
                    receivesRviImv: Boolean(req.body.economicCoverage?.items?.receivesRviImv)
                },
                observations: String(req.body.economicCoverage?.observations || '').trim()
            },
            details: String(req.body.details || '').trim(),
            location: {
                lat: Number(req.body.lat),
                lng: Number(req.body.lng)
            }
        };

        // Log de datos sanitizados
        logger.info('Datos sanitizados', { sanitizedData });

        const userId = req.params.userId;
        const errors = [];

        // Validaciones básicas
        if (!userId) {
            errors.push('El ID de usuario es requerido');
        }

        if (!sanitizedData.location?.lat || !sanitizedData.location?.lng) {
            errors.push('La ubicación es requerida');
        }

        // Validaciones de personalInfo
        const requiredPersonalInfoFields = [
            'fullName', 'idType', 'idNumber', 'birthDate', 
            'gender', 'language', 'residence', 'city', 'householdMembers', 'phone'
        ];

        requiredPersonalInfoFields.forEach(field => {
            if (!sanitizedData.personalInfo[field]) {
                errors.push(`El campo ${field} es requerido`);
            }
        });

        // Validación específica para householdMembers
        if (sanitizedData.personalInfo.householdMembers < 1) {
            errors.push('El número de miembros del hogar debe ser al menos 1');
        }

         // Validación específica para el teléfono
         if (!isValidPhone(sanitizedData.personalInfo.phone)) {
            errors.push('El formato del teléfono no es válido. Debe contener entre 9 y 15 dígitos y puede incluir código de país');
        }

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

        const decryptedUserId = crypt.decrypt(userId);
        
         // Obtener la institución del usuario
         const user = await User.findById(decryptedUserId);
         if (!user) {
             logger.warn('Usuario no encontrado al crear necesidad', {
                 userId: decryptedUserId,
                 ip: req.ip || req.connection.remoteAddress
             });
             return res.status(404).json({
                 success: false,
                 message: 'Usuario no encontrado'
             });
         }

        const newNeed = new Need({
            ...sanitizedData,
            userId: decryptedUserId,
            institution: user.institution,
            timestamp: new Date()
        });

        await newNeed.save();

        logger.info('Necesidad creada exitosamente', {
            needId: newNeed._id,
            userId: decryptedUserId
        });

        res.status(201).json({
            success: true,
            data: newNeed,
            message: 'Necesidad registrada correctamente'
        });

    } catch (error) {
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

const updateNeed = async (req, res) => {
    try {
        const needId = req.params.needId;
        const userId = req.params.userId;

        // Log del intento de actualización
        logger.info('Intento de actualización de necesidad', {
            needId,
            userId,
            ip: req.ip || req.connection.remoteAddress
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

        // Sanitizar los datos de actualización
        const sanitizedData = {
            personalInfo: req.body.personalInfo ? {
                fullName: String(req.body.personalInfo.fullName || '').trim(),
                idType: String(req.body.personalInfo.idType || '').trim(),
                idNumber: String(req.body.personalInfo.idNumber || '').trim(),
                lostDocumentation: Boolean(req.body.personalInfo.lostDocumentation),
                birthDate: req.body.personalInfo.birthDate ? new Date(req.body.personalInfo.birthDate) : undefined,
                gender: String(req.body.personalInfo.gender || '').trim(),
                language: String(req.body.personalInfo.language || '').trim(),
                residence: String(req.body.personalInfo.residence || '').trim(),
                city: String(req.body.personalInfo.city || '').trim(),
                householdMembers: Number(req.body.personalInfo.householdMembers),
                phone: String(req.body.personalInfo.phone || '').replace(/[\s-]/g, '').trim()
            } : undefined,
            housing: req.body.housing ? {
                items: {
                    noHousing: Boolean(req.body.housing.items?.noHousing),
                    housingDeficiencies: Boolean(req.body.housing.items?.housingDeficiencies),
                    unsanitary: Boolean(req.body.housing.items?.unsanitary),
                    overcrowding: Boolean(req.body.housing.items?.overcrowding),
                    noBasicGoods: Boolean(req.body.housing.items?.noBasicGoods),
                    foodShortage: Boolean(req.body.housing.items?.foodShortage)
                },
                observations: String(req.body.housing.observations || '').trim()
            } : undefined,
            employment: req.body.employment ? {
                items: {
                    allUnemployed: Boolean(req.body.employment.items?.allUnemployed),
                    jobLoss: Boolean(req.body.employment.items?.jobLoss),
                    temporaryLayoff: Boolean(req.body.employment.items?.temporaryLayoff),
                    precariousEmployment: Boolean(req.body.employment.items?.precariousEmployment)
                },
                observations: String(req.body.employment.observations || '').trim()
            } : undefined,
            socialNetworks: req.body.socialNetworks ? {
                items: {
                    socialIsolation: Boolean(req.body.socialNetworks.items?.socialIsolation),
                    neighborConflicts: Boolean(req.body.socialNetworks.items?.neighborConflicts),
                    needsInstitutionalSupport: Boolean(req.body.socialNetworks.items?.needsInstitutionalSupport),
                    vulnerableMinors: Boolean(req.body.socialNetworks.items?.vulnerableMinors)
                },
                observations: String(req.body.socialNetworks.observations || '').trim()
            } : undefined,
            publicServices: req.body.publicServices ? {
                items: {
                    noHealthCoverage: Boolean(req.body.publicServices.items?.noHealthCoverage),
                    discontinuedMedicalTreatment: Boolean(req.body.publicServices.items?.discontinuedMedicalTreatment),
                    unschooledMinors: Boolean(req.body.publicServices.items?.unschooledMinors),
                    dependencyWithoutAssessment: Boolean(req.body.publicServices.items?.dependencyWithoutAssessment),
                    mentalHealthIssues: Boolean(req.body.publicServices.items?.mentalHealthIssues)
                },
                observations: String(req.body.publicServices.observations || '').trim()
            } : undefined,
            socialParticipation: req.body.socialParticipation ? {
                items: {
                    memberOfOrganizations: Boolean(req.body.socialParticipation.items?.memberOfOrganizations),
                    receivesSocialServices: Boolean(req.body.socialParticipation.items?.receivesSocialServices)
                },
                observations: String(req.body.socialParticipation.observations || '').trim()
            } : undefined,
            economicCoverage: req.body.economicCoverage ? {
                items: {
                    noIncome: Boolean(req.body.economicCoverage.items?.noIncome),
                    pensionsOrBenefits: Boolean(req.body.economicCoverage.items?.pensionsOrBenefits),
                    receivesRviImv: Boolean(req.body.economicCoverage.items?.receivesRviImv)
                },
                observations: String(req.body.economicCoverage.observations || '').trim()
            } : undefined,
            details: req.body.details ? String(req.body.details).trim() : undefined,
            location: (req.body.lat || req.body.lng) ? {
                lat: Number(req.body.lat),
                lng: Number(req.body.lng)
            } : undefined,
            status: req.body.status ? String(req.body.status).trim() : undefined
        };

        // Log de datos sanitizados
        logger.info('Datos sanitizados para actualización', { 
            needId,
            sanitizedData 
        });

        const errors = [];

        // Validaciones específicas si se actualiza personalInfo
        if (sanitizedData.personalInfo) {
            const requiredPersonalInfoFields = [
                'fullName', 'idType', 'idNumber', 'birthDate', 
                'gender', 'language', 'residence', 'city', 'householdMembers', 'phone'
            ];

            requiredPersonalInfoFields.forEach(field => {
                if (!sanitizedData.personalInfo[field]) {
                    errors.push(`El campo ${field} es requerido`);
                }
            });

            if (sanitizedData.personalInfo.householdMembers < 1) {
                errors.push('El número de miembros del hogar debe ser al menos 1');
            }
            if (sanitizedData.personalInfo.phone && 
                !isValidPhone(sanitizedData.personalInfo.phone)) {
                errors.push('El formato del teléfono no es válido. Debe contener entre 9 y 15 dígitos y puede incluir código de país');
            }
        }

        // Validar ubicación si se proporciona
        if (sanitizedData.location && (!sanitizedData.location.lat || !sanitizedData.location.lng)) {
            errors.push('Si se proporciona ubicación, tanto lat como lng son requeridos');
        }

        if (sanitizedData.status) {
            const validStatuses = ['new', 'pending', 'in_progress', 'completed', 'cancelled'];
            if (!validStatuses.includes(sanitizedData.status)) {
                errors.push(`Estado inválido. Los estados válidos son: ${validStatuses.join(', ')}`);
            }
        }

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
};

const getAllNeedsComplete = async (req, res) => {
    try {
        console.log('getAllNeedsComplete')
        const userId = req.user;
        const userEncrypted = crypt.encrypt(userId)

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

         // Log de intento de obtención
         logger.info('Intento de obtención de todas las necesidades', {
            ip: req.ip || req.connection.remoteAddress,
            query: req.query, // Por si añadimos filtros en el futuro
            userId: userEncrypted
        });
        // Sanitizar parámetros de consulta si los hubiera
        const sanitizedQuery = {
            activated: true,
            // Aquí podrían ir más filtros sanitizados si se añaden en el futuro
        };
        // Si es admin (no superadmin), filtrar por institución
        if (user.role === 'Admin') {
            sanitizedQuery.institution = user.institution;
        }

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
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

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
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

const getAllNeedsForHeatmap = async (req, res) => {
    try {
        const userId = req.user;
        const userEncrypted = crypt.encrypt(userId)
        // Obtener el usuario y su rol
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Construir el query base
        let query = { activated: true, status: { $ne: 'helped' } };

        // Si es admin (no superadmin), filtrar por institución
        if (user.role === 'Admin') {
            query.institution = user.institution;
        }

        // Log de intento de obtención
        logger.info('Intento de obtención de necesidades para heatmap', {
            ip: req.ip || req.connection.remoteAddress,
            query: req.query,
            userId: userEncrypted,
            institution: user.institution,
            role: user.role
        });

        // Log de parámetros de búsqueda
        logger.info('Parámetros de búsqueda sanitizados para heatmap', {
            query,
            ip: req.ip || req.connection.remoteAddress
        });

        // Obtener necesidades
        const needs = await Need.find(query);

        // Validar el resultado
        if (!needs || needs.length === 0) {
            logger.info('No se encontraron necesidades para el heatmap', {
                query,
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
            location: need.location ? {
                lat: Number(need.location.lat),
                lng: Number(need.location.lng)
            } : null,
            timestamp: need.timestamp,
            _id: need._id,
            status: String(need.status || '').trim(),
            // Ocultar datos sensibles
            details: need.details ? '[Contenido privado]' : '',
            housing: need.housing?.items || {},
            employment: need.employment?.items || {},
            socialNetworks: need.socialNetworks?.items || {},
            publicServices: need.publicServices?.items || {},
            socialParticipation: need.socialParticipation?.items || {},
            economicCoverage: need.economicCoverage?.items || {}
        }));

        // Log de éxito con métricas
        logger.info('Datos del heatmap procesados', {
            totalNeeds: needs.length,
            needsWithLocation: sanitizedNeeds.filter(n => n.location).length,
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
            error: config.NODE_ENV === 'production' ? 
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
            error: config.NODE_ENV === 'production' ? 
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
            error: config.NODE_ENV === 'production' ? 
                'Error interno del servidor' : 
                error.message
        });
    }
};

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
            error: config.NODE_ENV === 'production' ? 
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
        const validStatuses = ['new','pending', 'in_progress', 'completed', 'cancelled'];
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
            error: config.NODE_ENV === 'production' ? 
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