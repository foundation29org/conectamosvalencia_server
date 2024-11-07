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
const config = require('./config');
//CORS middleware

app.disable('x-powered-by');

app.use(cookieParser());
/*app.use(helmet({
  contentSecurityPolicy: {
      directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
              "'self'",
              "'unsafe-inline'",
              "'unsafe-eval'",
              "https://apis.google.com",
              "https://maps.googleapis.com",
              "https://www.google.com",
              "https://www.gstatic.com",
              "https://kit.fontawesome.com",
              "https://www.googletagmanager.com",
              "https://static.hotjar.com"
          ],
          styleSrc: [
              "'self'",
              "'unsafe-inline'",
              "https://fonts.googleapis.com",
              "https://kit-free.fontawesome.com",
              "https://ka-f.fontawesome.com"
          ],
          imgSrc: [
              "'self'",
              "data:",
              "blob:",
              "https:",
              "https://maps.gstatic.com",
              "https://maps.googleapis.com"
          ],
          fontSrc: [
              "'self'",
              "data:",
              "https://fonts.gstatic.com",
              "https://kit-free.fontawesome.com",
              "https://ka-f.fontawesome.com"
          ],
          frameSrc: [
              "'self'",
              "https://www.google.com",
              "https://vars.hotjar.com"
          ],
          connectSrc: [
              "'self'",
              "http://localhost:8443",
              "https://apis.google.com",
              "https://maps.googleapis.com",
              "https://*.hotjar.com",
              "wss://*.hotjar.com",
              "https://*.google-analytics.com",
              "https://analytics.google.com",
              "https://stats.g.doubleclick.net",
              "https://ka-f.fontawesome.com"
          ],
          workerSrc: ["'self'", "blob:"],
          childSrc: ["blob:"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"]
      }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false
}));

// Añadir cabeceras de seguridad adicionales
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 
      'geolocation=(self), camera=(), microphone=(), payment=(), usb=()');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
*/


app.use(helmet({
  hidePoweredBy: true, // Ocultar cabecera X-Powered-By
  contentSecurityPolicy: {
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "https://apis.google.com",
            "https://maps.googleapis.com",
            "https://www.google.com",
            "https://www.gstatic.com",
            "https://kit.fontawesome.com",
            "https://www.googletagmanager.com",
            "https://static.hotjar.com",
            "https://script.hotjar.com",
            "https://region1.google-analytics.com",
            "https://maps-api-v3.googleapis.com"
        ],
        styleSrc: [
            "'self'",
            "'unsafe-inline'",
            "https://fonts.googleapis.com",
            "https://kit-free.fontawesome.com",
            "https://ka-f.fontawesome.com"
        ],
        imgSrc: [
            "'self'",
            "data:",
            "blob:",
            "https:",
            "https://maps.gstatic.com",
            "https://maps.googleapis.com",
            "https://foundation29.org"
        ],
        fontSrc: [
            "'self'",
            "data:",
            "https://fonts.gstatic.com",
            "https://kit-free.fontawesome.com",
            "https://ka-f.fontawesome.com",
            "https://script.hotjar.com"
        ],
        frameSrc: [
            "'self'",
            "https://www.google.com",
            "https://vars.hotjar.com"
        ],
        connectSrc: [
            "'self'",
            "http://localhost:8443",
            "https://apis.google.com",
            "https://maps.googleapis.com",
            "https://*.hotjar.com",
            "wss://*.hotjar.com",
            "https://*.hotjar.io",
            "https://*.google-analytics.com",
            "https://analytics.google.com",
            "https://stats.g.doubleclick.net",
            "https://ka-f.fontawesome.com",
            "https://region1.google-analytics.com"
        ],
        workerSrc: ["'self'", "blob:"],
        childSrc: ["blob:"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"]
    }
  },
  frameguard: {
      action: 'DENY'
  },
  hidePoweredBy: true,
  hsts: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  xssFilter: true,
  referrerPolicy: {
      policy: 'no-referrer-when-downgrade'
  },
  crossOriginEmbedderPolicy: false,  // Necesario para recursos de terceros
}));

app.use(cors({
    origin: config.NODE_ENV === 'production' 
        ? ['https://conectamosvalencia.com', 'https://www.conectamosvalencia.com'] // Dominio en producción
        : ['http://localhost:4200'], // Dominio en desarrollo
    credentials: true,
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Accept-Language', 'Origin', 'User-Agent'],
    exposedHeaders: ['set-cookie']
}));
// Añadir manualmente algunas cabeceras adicionales de seguridad
app.use((req, res, next) => {
  // Eliminar cabeceras que exponen información
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Permissions-Policy', 
    'geolocation=(), camera=(), microphone=(), payment=(), usb=()');
  next();
});

app.use(bodyParser.urlencoded({
  limit: '1mb', 
  extended: false,
  parameterLimit: 1000 // Limitar número de parámetros
}));

app.use(bodyParser.json({
  limit: '1mb',
  strict: true // Rechazar payload que no sea JSON válido
}));

// Logging de desarrollo (solo si es necesario)
if (config.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
      console.log('Request cookies:', req.cookies);
      console.log('Request headers:', req.headers);
      next();
  });
}

// use the forward slash with the module api api folder created routes
app.use('/api',api)

app.use('/apidoc',express.static('apidoc', {'index': ['index.html']}))

//ruta angular, poner carpeta dist publica
app.use(express.static(path.join(__dirname, 'dist')));
// Send all other requests to the Angular app
app.get('*', function (req, res, next) {
    res.sendFile('dist/index.html', { root: __dirname });
 });
module.exports = app
