// Support schema
'use strict'

const mongoose = require ('mongoose');
const Schema = mongoose.Schema
const User = require('./user')
const crypt = require('../services/crypt')

const { conndbaccounts } = require('../db_connect')

const SupportSchema = Schema({
	platform: String,
	subject: String,
	description: String,
	type: String,
	status: {type: String, default: 'unread'},
	statusDate: {type: Date, default: Date.now},
	files: Object,
	date: {type: Date, default: Date.now},
	createdBy: { type: Schema.Types.ObjectId, ref: "User"}
})

SupportSchema.pre('save', function (next) {
	this.description = crypt.encrypt(this.description)
	this.subject = crypt.encrypt(this.subject)
	next();
});

SupportSchema.post('save', function (document) {
	if(document !== null){
		document.description = crypt.decrypt(document.description)
		document.subject = crypt.decrypt(document.subject)
	}
});

SupportSchema.post('findOne', function (document) {
	if(document !== null){
		document.description = crypt.decrypt(document.description)
		document.subject = crypt.decrypt(document.subject)
	}
});

SupportSchema.post('find', function (documents) {
	if(documents !== null){
		//console.log(documents)
		documents.forEach(function(document) {
			document.description = crypt.decrypt(document.description)
			document.subject = crypt.decrypt(document.subject)
		});
	}
});

SupportSchema.post('findById', function (document) {
	if(document !== null){
		document.description = crypt.decrypt(document.description)
		document.subject = crypt.decrypt(document.subject)
	}
});

SupportSchema.post('findByIdAndUpdate', function (document) {
	if(document !== null){
		document.description = crypt.decrypt(document.description)
		document.subject = crypt.decrypt(document.subject)
	}
});

module.exports = conndbaccounts.model('Support',SupportSchema)
// we need to export the model so that it is accessible in the rest of the app
