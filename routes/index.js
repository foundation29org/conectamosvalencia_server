// file that contains the routes of the api
'use strict'

const express = require('express')
const needsCtrl = require('../controllers/needs')

const userCtrl = require('../controllers/all/user')

const admninUsersCtrl = require('../controllers/admin/users')

const auth = require('../middlewares/auth')
const roles = require('../middlewares/roles')
const api = express.Router()
const cors = require('cors')
const config = require('../config')
const needsLimiter = require('../middlewares/rateLimiter')

const whitelist = config.allowedOrigins;


function corsWithOptions(req, res, next) {
  const corsOptions = {
    origin: function (origin, callback) {
      console.log('Origin:', origin);
      console.log('Host:', req.headers.host);
      
      // Verificar que el host es el esperado
      const isValidHost = req.headers.host && (
        req.headers.host === 'conectamosvalencia.com' ||          // Producción
        req.headers.host.includes('conectamosvalencia.com') ||    // Subdominio en producción
        req.headers.host.includes('localhost:') ||                // Desarrollo local
        req.headers.host.includes('127.0.0.1:')                  // Alternativa localhost
      );

      if (!isValidHost) {
        console.log('Invalid host:', req.headers.host);
        callback(new Error('Invalid host'));
        return;
      }

      // Si es same-origin (Sec-Fetch-Site: same-origin)
      if (req.headers['sec-fetch-site'] === 'same-origin') {
        callback(null, true);
        return;
      }
      
      // Para peticiones cross-origin, verificar whitelist
      if (whitelist.includes(origin)) {
        callback(null, true);
      } else {
        console.log('CORS error - Origin not allowed:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  };

  cors(corsOptions)(req, res, next);
}

// user routes, using the controller user, this controller has methods
//routes for login-logout



api.post('/signup', corsWithOptions, needsLimiter, userCtrl.signUp)
api.post('/login', corsWithOptions, needsLimiter, userCtrl.login)
api.get('/me', corsWithOptions, needsLimiter, userCtrl.getMe)
api.post('/logout', corsWithOptions, needsLimiter, userCtrl.logout)
api.post('/checkLogin', corsWithOptions, needsLimiter, userCtrl.checkLogin)
api.post('/activateuser/:userId', corsWithOptions, needsLimiter, auth(roles.SuperAdmin), userCtrl.activateUser)
api.post('/deactivateuser/:userId', corsWithOptions, needsLimiter, auth(roles.SuperAdmin), userCtrl.deactivateUser)


api.get('/admin/allusers', corsWithOptions, needsLimiter, auth(roles.SuperAdmin), admninUsersCtrl.getAllUsers)


api.post('/needs/:userId', corsWithOptions, needsLimiter, auth(roles.AllLessResearcher), needsCtrl.createNeed)
api.put('/needs/:userId/:needId', corsWithOptions, needsLimiter, auth(roles.AllLessResearcher), needsCtrl.updateNeed)
api.delete('/needs/:userId/:needId', corsWithOptions, needsLimiter, auth(roles.AllLessResearcher), needsCtrl.deleteNeed)
api.delete('/superadmin/needs/:needId', corsWithOptions, needsLimiter, auth(roles.SuperAdmin), needsCtrl.superadminDeleteNeed)
api.get('/needs/phone/:needId', corsWithOptions, needsLimiter, auth(roles.AdminSuperAdmin), needsCtrl.getPhone)
api.get('/needs', corsWithOptions, auth(roles.AdminSuperAdmin), needsLimiter, needsCtrl.getAllNeedsForHeatmap)
api.get('/needs/complete', corsWithOptions, auth(roles.AdminSuperAdmin), needsLimiter, needsCtrl.getAllNeedsComplete)
api.get('/needsuser/complete/:userId', corsWithOptions, auth(roles.AllLessResearcher), needsLimiter, needsCtrl.getAllNeedsCompleteForUser)
api.put('/status/needs/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsLimiter, needsCtrl.updateStatus)

/*api.get('/testToken', auth, (req, res) => {
	res.status(200).send(true)
})*/
//ruta privada
api.get('/private', auth(roles.AllLessResearcher), (req, res) => {
	res.status(200).send({ message: 'You have access' })
})

module.exports = api
