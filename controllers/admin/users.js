// functions for each call of the api on admin. Use the user model

'use strict'

// add the user model
const User = require('../../models/user')
const crypt = require('../../services/crypt')



async function getAllUsers(req, res) {
	try {
		var data = await getInfoUser();
		return res.status(200).send(data)
	} catch (e) {
		console.error("Error: ", e);
	}
}

async function getInfoUser() {
    return new Promise(async (resolve, reject) => {
        try {
            const users = await User.find(
                { role: 'Admin' }, 
                'userName position institution phone confirmed email'
            );
            
            if (!users || users.length === 0) {
                resolve([]);
                return;
            }

            const usersInfo = users.map(user => ({
                userId: crypt.encrypt(user._id.toString()),
                userName: user.userName || '',
                email: user.email || '',
                position: user.position || '',
                institution: user.institution || '',
                phone: user.phone || '',
                confirmed: user.confirmed || false
            }));

            resolve(usersInfo);

        } catch (error) {
            console.error('Error obteniendo usuarios admin:', error);
            reject(error);
        }
    });
}




module.exports = {
	getAllUsers
}
