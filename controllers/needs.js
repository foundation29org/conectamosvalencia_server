const Need = require('../models/need');
const crypt = require('../services/crypt')
const User = require('../models/user');

const createNeed = async (req, res) => {
    try {
        // Extraer los datos del body de la petición
        const userId = req.params.userId;
        const { type, needs, otherNeeds, details, location, timestamp } = req.body;

        // Array para almacenar mensajes de error
        const errors = [];

        // Validar tipo
        if (!type) {
            errors.push('El tipo es requerido');
        } else if (!['need', 'offer'].includes(type)) {
            errors.push('El tipo debe ser "need" u "offer"');
        }

        // Validar userId
        if (!userId) {
            errors.push('El ID de usuario es requerido');
        }

        // Validar necesidades
        if (!needs && !otherNeeds) {
            errors.push('Debe especificar al menos una necesidad o completar otras necesidades');
        }

        // Validar ubicación para necesidades
        if (type === 'need') {
            if (!location || !location.lat || !location.lng) {
                errors.push('La ubicación es requerida para las necesidades');
            }
        }

        // Si hay errores, retornar respuesta con todos los errores
        if (errors.length > 0) {
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
            type,
            needs,
            otherNeeds,
            details,
            location: {
                lat: location.lat,
                lng: location.lng
            },
            timestamp: timestamp || new Date(),
            userId: decryptedUserId
        });

        // Guardar en la base de datos
        await newNeed.save();

        // Responder con éxito
        res.status(201).json({
            success: true,
            data: newNeed,
            message: 'Necesidad registrada correctamente'
        });

    } catch (error) {
        console.error('Error al crear necesidad:', error);
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
        const decryptedUserId = crypt.decrypt(userId);

        // Verificar si la necesidad existe
        const need = await Need.findById(needId);
        if (!need) {
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        // Verificar permisos
        if (need.userId !== decryptedUserId) {
            return res.status(403).json({
                success: false,
                message: 'No tienes permisos para actualizar esta necesidad'
            });
        }

        // Validar los datos de actualización
        const { type, needs, otherNeeds, details, location } = req.body;
        const errors = [];

        // Validar tipo
        if (type && !['need', 'offer'].includes(type)) {
            errors.push('El tipo debe ser "need" u "offer"');
        }

        // Validar necesidades
        if (!needs && !otherNeeds) {
            errors.push('Debe especificar al menos una necesidad o completar otras necesidades');
        }

        // Validar ubicación para necesidades
        if (type === 'need') {
            if (!location || !location.lat || !location.lng) {
                errors.push('La ubicación es requerida para las necesidades');
            }
        }

        // Si hay errores de validación, retornar error
        if (errors.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Error de validación',
                errors: errors
            });
        }

        // Actualizar la necesidad
        const updatedNeed = await Need.findByIdAndUpdate(
            needId, 
            {
                ...req.body,
                timestamp: new Date() // Actualizar timestamp si es necesario
            }, 
            { 
                new: true,
                runValidators: true // Ejecutar validadores del esquema
            }
        );

        res.status(200).json({
            success: true,
            data: updatedNeed,
            message: 'Necesidad actualizada correctamente'
        });
    } catch (error) {
        console.error('Error al actualizar necesidad:', error);
        res.status(500).json({
            success: false,
            message: 'Error al actualizar la necesidad',
            error: error.message
        });
    }
}

const getAllNeedsComplete = async (req, res) => {
    try {
        // Obtener todas las necesidades
        // Puedes añadir .sort({ timestamp: -1 }) si quieres ordenar por fecha descendente
        const needs = await Need.find({ 
            //status: { $ne: 'completed' },
            activated: true  // Añadir este filtro
        });
        res.status(200).json({
            success: true,
            data: needs,
            count: needs.length
        });

    } catch (error) {
        console.error('Error al obtener necesidades:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: error.message
        });
    }
};

//crea esta funcion api.get('/needsuser/complete/:userId', corsWithOptions, auth(roles.AllLessResearcher), needsCtrl.getAllNeedsCompleteForUser)
const getAllNeedsCompleteForUser = async (req, res) => {
    try {
        const { userId } = req.params;
        //decrypt userId
        const decryptedUserId = crypt.decrypt(userId);
        const needs = await Need.find({ 
            userId: decryptedUserId,
            activated: true  // Añadir este filtro
        });
        res.status(200).json({
            success: true,
            data: needs,
            count: needs.length
        });

    } catch (error) {
        console.error('Error al obtener necesidades:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: error.message
        });
    }
}

const getAllNeedsForHeatmap = async (req, res) => {
    try {
        const needs = await Need.find({ 
            activated: true  // Añadir este filtro
        });
        
        // Transformamos los datos antes de enviarlos
        const sanitizedNeeds = needs.map(need => ({
            type: need.type,
            needs: need.needs,
            location: need.location,
            timestamp: need.timestamp,
            _id: need._id,
            status: need.status,
            otherNeeds: need.otherNeeds ? '[Contenido privado]' : '',
            details: need.details ? '[Contenido privado]' : ''
        }));

        res.status(200).json({
            success: true,
            data: sanitizedNeeds,
            count: needs.length
        });

    } catch (error) {
        console.error('Error al obtener necesidades:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: error.message
        });
    }
};

const deleteNeed = async (req, res) => {
    try {
        const needId = req.params.needId;
        const userId = req.params.userId;
        const decryptedUserId = crypt.decrypt(userId);
        const need = await Need.findById(needId);
        if (need.userId !== decryptedUserId) {
            return res.status(403).json({
                success: false,
                message: 'No tienes permisos para actualizar esta necesidad'
            });
        }

        
        if (!needId) {
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad no proporcionado'
            });
        }

        const deletedNeed = await Need.findByIdAndRemove(needId);

        if (!deletedNeed) {
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Necesidad eliminada correctamente'
        });

    } catch (error) {
        console.error('Error al eliminar necesidad:', error);
        res.status(500).json({
            success: false,
            message: 'Error al eliminar la necesidad',
            error: error.message
        });
    }
};

const superadminDeleteNeed = async (req, res) => {
    try {
        const needId = req.params.needId;
        
        if (!needId) {
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad no proporcionado'
            });
        }

        const deletedNeed = await Need.findByIdAndRemove(needId);

        if (!deletedNeed) {
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Necesidad eliminada correctamente'
        });

    } catch (error) {
        console.error('Error al eliminar necesidad:', error);
        res.status(500).json({
            success: false,
            message: 'Error al eliminar la necesidad',
            error: error.message
        });
    }
};

//crea esta funcion api.get('/needs/phone/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.getAllNeedsForPhone)
const getPhone = async (req, res) => {
    try {
        const needId = req.params.needId;
        //tienes que coger el userId de la necesidad y devolver el telefono de la coleccion users
        const need = await Need.findOne({ 
            _id: needId,
            activated: true  // Añadir este filtro
        });
        const user = await User.findById(need.userId);
        console.log(user);
        res.status(200).json({
            success: true,
            data: user.phone
        });
    } catch (error) {
        console.error('Error al obtener necesidades:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener las necesidades',
            error: error.message
        });
    }
}

//change status
const updateStatus = async (req, res) => {
    try {
        const { needId } = req.params;
        const { status } = req.body;

        if (!needId || !status) {
            return res.status(400).json({
                success: false,
                message: 'ID de necesidad y/o estado no proporcionado'
            });
        }

        const updatedNeed = await Need.findByIdAndUpdate(needId, { status }, { new: true });

        if (!updatedNeed) {
            return res.status(404).json({
                success: false,
                message: 'Necesidad no encontrada'
            });
        }

        res.status(200).json({
            success: true,
            data: updatedNeed,
            message: 'Estado actualizado correctamente'
        });

    } catch (error) {
        console.error('Error al actualizar estado de necesidad:', error);
        res.status(500).json({
            success: false,
            message: 'Error al actualizar el estado de la necesidad',
            error: error.message
        });
    }
}

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