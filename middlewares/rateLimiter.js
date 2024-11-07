const rateLimit = require('express-rate-limit');

const needsLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // límite por IP
    message: {
        success: false,
        message: 'Demasiadas peticiones, por favor intente más tarde'
    },
    handler: (req, res, next, options) => {
        console.warn('Rate limit exceeded:', {
            ip: req.ip,
            userId: req.params.userId,
            timestamp: new Date()
        });
        res.status(429).json(options.message);
    }
});

module.exports = needsLimiter;