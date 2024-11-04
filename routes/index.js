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

const whitelist = config.allowedOrigins;


function corsWithOptions(req, res, next) {
  const corsOptions = {
    origin: function (origin, callback) {
      console.log('Origin:', origin);
      console.log('Host:', req.headers.host);
      
      // Verificar que el host es el esperado
      const isValidHost = req.headers.host && (
        req.headers.host.includes('ayudamosvalencia.com') ||
        req.headers.host.includes('localhost:') ||  // Para desarrollo local
        req.headers.host.includes('127.0.0.1:')    // Alternativa localhost
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



api.post('/signup', corsWithOptions, userCtrl.signUp)

api.post('/login', corsWithOptions, userCtrl.login)
api.post('/checkLogin', corsWithOptions, userCtrl.checkLogin)



api.post('/activateuser/:userId', corsWithOptions, auth(roles.SuperAdmin), userCtrl.activateUser)
api.post('/deactivateuser/:userId', corsWithOptions, auth(roles.SuperAdmin), userCtrl.deactivateUser)


api.get('/admin/allusers', corsWithOptions, auth(roles.AdminSuperAdmin), admninUsersCtrl.getAllUsers)


api.post('/needs/:userId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.createNeed)
api.put('/needs/:userId/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.updateNeed)
api.delete('/needs/:userId/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.deleteNeed)

//needs/phone
api.get('/needs/phone/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.getPhone)


api.get('/needs', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.getAllNeedsForHeatmap)
api.get('/needs/complete', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.getAllNeedsComplete)
api.get('/needsuser/complete/:userId', corsWithOptions, auth(roles.AllLessResearcher), needsCtrl.getAllNeedsCompleteForUser)
//api.delete('/needs/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.deleteNeed)
//update status
api.put('/needs/status/:needId', corsWithOptions, auth(roles.AdminSuperAdmin), needsCtrl.updateStatus)

/*api.get('/testToken', auth, (req, res) => {
	res.status(200).send(true)
})*/
//ruta privada
api.get('/private', auth(roles.AllLessResearcher), (req, res) => {
	res.status(200).send({ message: 'You have access' })
})

module.exports = api
