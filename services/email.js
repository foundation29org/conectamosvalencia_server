'use strict'

const { TRANSPORTER_OPTIONS, client_server} = require('../config')
const nodemailer = require('nodemailer')
var hbs = require('nodemailer-express-handlebars')

var options = {
     viewEngine: {
         extname: '.hbs',
         layoutsDir: 'views/email/',
         defaultLayout : 'template'
     },
     viewPath: 'views/email/',
     extName: '.hbs'
 };

 var transporter = nodemailer.createTransport(TRANSPORTER_OPTIONS);
 transporter.use('compile', hbs(options));

function sendMailFailSend (email){
    var maillistbcc = [
      TRANSPORTER_OPTIONS.auth.user,
      "maria.larrabe@foundation29.org"
    ];

    var emailToFinal = 'support@foundation29.org'
    var mailOptions = {
      to: emailToFinal,
      from: TRANSPORTER_OPTIONS.auth.user,
      bcc: maillistbcc,
      subject: 'Message for support. Fail email ConectamosValencia: '+ email,
      template: 'mail_support/fail',
      context: {
        email : email
      }
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.log(error);
      } else {
        console.log('send ok');
      }
    });

  
}

function sendMailSupport (email, supportStored, emailTo){
  const decoded = new Promise((resolve, reject) => {
    var maillistbcc = [
    ];

    var emailToFinal = 'support@foundation29.org'
    if(emailTo!=null){
      emailToFinal = emailTo;
    }

    var mailOptions = {
      to: emailToFinal,
      from: TRANSPORTER_OPTIONS.auth.user,
      bcc: maillistbcc,
      subject: 'Message for support. ConectamosValencia Id: '+ supportStored._id,
      template: 'mail_support/_es',
      context: {
        email : email,
        info: supportStored
      }
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.log(error);
        sendMailFailSend(email)
        reject({
          status: 401,
          message: 'Fail sending email'
        })
      } else {
        resolve("ok")
      }
    });

  });
  return decoded
}

function sendMailAccountActivated (email, userName){
  var subjectlang='ConectamosValencia - Cuenta activada';
  const decoded = new Promise((resolve, reject) => {
    var maillistbcc = [
      TRANSPORTER_OPTIONS.auth.user
    ];

    var mailOptions = {
      to: email,
      from: TRANSPORTER_OPTIONS.auth.user,
      bcc: maillistbcc,
      subject: subjectlang,
      template: 'active_account/_es',
      context: {
        client_server : client_server,
        userName : userName
      }
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.log(error);
        sendMailFailSend(email)
        reject({
          status: 401,
          message: 'Fail sending email'
        })
      } else {
        resolve("ok")
      }
    });

  });
  return decoded


}

function sendMailAccountDeactivated (email, userName){
  var subjectlang='ConectamosValencia - Cuenta desactivada';
  const decoded = new Promise((resolve, reject) => {
    var maillistbcc = [
      TRANSPORTER_OPTIONS.auth.user
    ];

    var mailOptions = {
      to: email,
      from: TRANSPORTER_OPTIONS.auth.user,
      bcc: maillistbcc,
      subject: subjectlang,
      template: 'desactive_account/_es',
      context: {
        client_server : client_server,
        userName : userName
      }
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.log(error);
        sendMailFailSend(email)
        reject({
          status: 401,
          message: 'Fail sending email'
        })
      } else {
        resolve("ok")
      }
    });

  });
  return decoded


}

function sendEmailLogin (email, randomstring){
  var subject='Link de acceso para ConectamosValencia';
  const decoded = new Promise((resolve, reject) => {

    var maillistbcc = [
      'support@foundation29.org',
    ];
    var mailOptions = {
      to: email,
      from:'support@foundation29.org',
      subject: subject,
      template: 'login_pass/_es',
      context: {
        client_server : client_server,
        email : email,
        key : randomstring
      }
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.log(error);
        reject({
          status: 401,
          message: 'Fail sending email'
        })
      } else {
        console.log('Email sent: ' + info.response);
        resolve("ok")
      }
    });

  });
  return decoded
}

module.exports = {
  sendMailSupport,
  sendMailAccountActivated,
  sendMailAccountDeactivated,
  sendEmailLogin
}
