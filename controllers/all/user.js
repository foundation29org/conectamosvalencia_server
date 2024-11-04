// functions for each call of the api on user. Use the user model

'use strict'

// add the user model
const User = require('../../models/user')
const serviceAuth = require('../../services/auth')
const serviceEmail = require('../../services/email')
const crypt = require('../../services/crypt')
const config = require('../../config')

function login(req, res) {
	// attempt to authenticate user
	req.body.email = (req.body.email).toLowerCase();
	User.getAuthenticated(req.body.email, function (err, user, reason) {
		if (err) return res.status(500).send({ message: err })
		let randomstring = Math.random().toString(36).slice(-12);
		let dateTimeLogin = Date.now();
		if (!user) {
			//return res.status(500).send({ message: `Fail` })
			var reasons = User.failedLogin;
			switch (reason) {
				case reasons.NOT_FOUND:
					return res.status(202).send({
						message: 'Login failed'
					})
					break;
				case reasons.PASSWORD_INCORRECT:
					// note: these cases are usually treated the same - don't tell
					// the user *why* the login failed, only that it did
					return res.status(202).send({
						message: 'Login failed'
					})
					break;
				case reasons.MAX_ATTEMPTS:
					// send email or otherwise notify user that account is
					// temporarily locked
					return res.status(202).send({
						message: 'Account is temporarily locked'
					})
					break;
				case reasons.UNACTIVATED:
					return res.status(202).send({
						message: 'Account is unactivated'
					})
					break;
				case reasons.BLOCKED:
					return res.status(202).send({
						message: 'Account is blocked'
					})
					break;
			}
		} else {
			User.findOne({ 'email': req.body.email }, function (err, user2) {
				if (err){
					insights.error(err);
					return res.status(500).send({ message: `Error creating the user: ${err}` })
				}
				if (!user2) {
					return res.status(500).send({ message: `Fail` })
				} else {
					User.findByIdAndUpdate(user2._id, { confirmationCode: randomstring, dateTimeLogin: dateTimeLogin }, { new: true }, (err, userUpdated) => {
						if (err){
							insights.error(err);
							return res.status(500).send({ message: `Error making the request: ${err}` })
						}else{
							if(userUpdated){
								//send email
								serviceEmail.sendEmailLogin(userUpdated.email, userUpdated.confirmationCode)
								return res.status(200).send({
									message: 'Check email'
								})
							}else{
								insights.error("The user does not exist");
								return res.status(404).send({ code: 208, message: `The user does not exist` })
							}
							
						}
						
					})
				}
			})
		}

	})
}

function checkLogin(req, res) {
	User.findOne({ 'email': req.body.email, 'confirmationCode': req.body.confirmationCode }, function (err, user2) {
		if (err){
			insights.error(err);
			return res.status(500).send({ message: `Error creating the user: ${err}` })
		}
		if (!user2) {
			return res.status(500).send({ message: `Fail` })
		} else {
			var limittime = new Date(); // just for example, can be any other time
			var myTimeSpan = 5*60*1000; // 5 minutes in milliseconds
			limittime.setTime(limittime.getTime() - myTimeSpan);
			if(limittime.getTime() < user2.dateTimeLogin.getTime()){
				return res.status(200).send({
					message: 'You have successfully logged in',
					token: serviceAuth.createToken(user2)
				})
			}else{
				return res.status(200).send({
					message: 'Link expired'
				})
			}
		}
	})
}

const activateUser = async (req, res) => {
    try {
        // Desencriptar el userId del parámetro
        const userId = crypt.decrypt(req.params.userId);
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no válido'
            });
        }

        // Buscar el usuario y actualizar su estado
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { 
                confirmed: true,
                dateConfirmed: new Date()
            },
            {
                select: '-createdBy -loginAttempts -confirmationCode',
                new: true
            }
        );

        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Enviar email de confirmación al usuario
        try {
            await serviceEmail.sendMailAccountActivated(updatedUser.email, updatedUser.userName);
        } catch (emailError) {
            console.error('Error enviando email de confirmación:', emailError);
            // Continuamos aunque falle el email
        }

        return res.status(200).json({
            success: true,
            message: 'Usuario activado correctamente',
            data: {
                email: updatedUser.email,
                userName: updatedUser.userName,
                confirmed: updatedUser.confirmed,
                dateConfirmed: updatedUser.dateConfirmed
            }
        });

    } catch (error) {
        console.error('Error activando usuario:', error);
        return res.status(500).json({
            success: false,
            message: 'Error al activar el usuario',
            error: error.message
        });
    }
};


//crear metodo para desactivar cuenta
const deactivateUser = async (req, res) => {
    try {
        // Desencriptar el userId del parámetro
        const userId = crypt.decrypt(req.params.userId);
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'ID de usuario no válido'
            });
        }

        // Buscar el usuario y actualizar su estado
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { 
                confirmed: false,
                dateDeactivated: new Date()
            },
            {
                select: '-createdBy -loginAttempts -confirmationCode',
                new: true
            }
        );

        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Enviar email de notificación al usuario
        try {
            await serviceEmail.sendMailAccountDeactivated(updatedUser.email, updatedUser.userName);
        } catch (emailError) {
            console.error('Error enviando email de desactivación:', emailError);
            // Continuamos aunque falle el email
        }

        return res.status(200).json({
            success: true,
            message: 'Usuario desactivado correctamente',
            data: {
                email: updatedUser.email,
                userName: updatedUser.userName,
                confirmed: updatedUser.confirmed,
                dateDeactivated: updatedUser.dateDeactivated
            }
        });

    } catch (error) {
        console.error('Error desactivando usuario:', error);
        return res.status(500).json({
            success: false,
            message: 'Error al desactivar el usuario',
            error: error.message
        });
    }
};

/**
 * @api {post} https://conectamosvalencia.com/api/api/signUp New account
 * @apiName signUp
 * @apiVersion 1.0.0
 * @apiGroup Account
 * @apiDescription This method allows you to create a user account in ConectamosValencia
 * @apiExample {js} Example usage:
 *  var passwordsha512 = sha512("fjie76?vDh");
 *  var formValue = { email: "example@ex.com", userName: "Peter", password: passwordsha512, lang: "en", group: "None"};
 *   this.http.post('https://conectamosvalencia.com/api/signup',formValue)
 *    .subscribe( (res : any) => {
 *      if(res.message == "Account created"){
 *        console.log("Check the email to activate the account");
 *      }else if(res.message == 'Fail sending email'){
 *        //contact with health29
 *      }else if(res.message == 'user exists'){
 *       ...
 *      }
 *   }, (err) => {
 *     ...
 *   }
 *
 * @apiParam (body) {String} email User email
 * @apiParam (body) {String} userName User name
 * @apiParam (body) {String} password User password using hash <a href="https://es.wikipedia.org/wiki/SHA-2" target="_blank">sha512</a>
 * @apiParam (body) {String} lang Lang of the User. For this, go to  [Get the available languages](#api-Languages-getLangs).
 * We currently have 5 languages, but we will include more. The current languages are:
 * * English: en
 * * Spanish: es
 * * German: de
 * * Dutch: nl
 * * Portuguese: pt
 * @apiParam (body) {String} [group] Group to which the user belongs, if it does not have a group or do not know the group to which belongs, it will be 'None'. If the group is not set, it will be set to 'None' by default.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "email": "example@ex.com",
 *       "userName": "Peter",
 *       "password": "f74f2603939a53656948480ce71f1ce46457b6654fd22c61c1f2ccd3e2c96d1cd02d162b560c4beaf1ae45f4574571dc5cbc1ce040701c0b5c38457988aa00fe97f",
 *       "group": "None",
 *       "lang": "en"
 *     }
 * @apiSuccess {String} message Information about the request. One of the following answers will be obtained:
 * * Account created (The user should check the email to activate the account)
 * * Fail sending email
 * * user exists
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *  "message": "Account created"
 * }
 *
 */


function signUp(req, res) {
	let secretKey = config.secretCaptcha; //the secret key from your google admin console;
	let token = req.body.captchaToken

  	//if passed response success message to client
	  req.body.email = (req.body.email).toLowerCase();
	  const user = new User({
		  email: req.body.email,
		  userName: req.body.userName,
		  position: req.body.position,
		  institution: req.body.institution,
		  phone: req.body.phone,
		  platform: 'ConectamosValencia'
	  })
	  User.findOne({ 'email': req.body.email }, function (err, user2) {
		  if (err) return res.status(500).send({ message: `Error creating the user: ${err}` })
		  if (!user2) {
			  user.save((err, userSaved) => {
				  if (err) return res.status(500).send({ message: `Error creating the user: ${err}` })
				  res.status(200).send({ message: 'Account created' })
			  })
		  } else {
			  return res.status(202).send({ message: 'user exists' })
		  }
	  })

	
  
	
}

module.exports = {
	login,
	checkLogin,
	activateUser,
	deactivateUser,
	signUp
}
