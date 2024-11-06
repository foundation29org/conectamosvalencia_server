/*
* EXPRESS CONFIGURATION FILE
*/
'use strict'

const express = require('express')
const bodyParser = require('body-parser');
const app = express()
const api = require ('./routes')
const path = require('path')
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
//CORS middleware

app.use(cookieParser());
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://conectamosvalencia.com', 'https://www.conectamosvalencia.com'] // Dominio en producción
        : ['http://localhost:4200'], // Dominio en desarrollo
    credentials: true,
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Accept-Language', 'Origin', 'User-Agent'],
    exposedHeaders: ['set-cookie']
}));

// Configuración de seguridad
app.use(helmet({
  contentSecurityPolicy: false, // Deshabilitar CSP para compatibilidad
  frameguard: true,
  hidePoweredBy: true,
  hsts: true,
  ieNoOpen: true,
  noSniff: true,
  xssFilter: true
}));

app.use(bodyParser.urlencoded({limit: '50mb', extended: false}))
app.use(bodyParser.json({limit: '50mb'}))
// Añadir antes de las rutas
app.use((req, res, next) => {
  console.log('Request cookies:', req.cookies);
  console.log('Request headers:', req.headers);
  next();
});
// use the forward slash with the module api api folder created routes
app.use('/api',api)

app.use('/apidoc',express.static('apidoc', {'index': ['index.html']}))

/*app.use(express.static(path.join(__dirname, 'apidoc')));*/
/*app.get('/doc', function (req, res) {
    res.sendFile('apidoc/index.html', { root: __dirname });
 });*/

//ruta angular, poner carpeta dist publica
app.use(express.static(path.join(__dirname, 'dist')));
// Send all other requests to the Angular app
app.get('*', function (req, res, next) {
    res.sendFile('dist/index.html', { root: __dirname });
 });
module.exports = app
