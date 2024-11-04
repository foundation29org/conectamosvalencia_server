// Group schema
'use strict'

const mongoose = require ('mongoose');
const Schema = mongoose.Schema

const { conndbaccounts } = require('../db_connect')

const GroupSchema = Schema({
	name: {
		type: String
  },
	subscription: String,
	email: String,
	order: Number,
	defaultLang: {type: String, default: 'en'},
	phenotype: {type: Object, default: []},
	medications: {type: Object, default: []},
	notifications: {type: Object, default: {
		isNew: true,
		changeData: true,
		updatedBy: null
	}},
	translations: {type: Object, default: []},
})

module.exports = conndbaccounts.model('Group',GroupSchema)
// we need to export the model so that it is accessible in the rest of the app
