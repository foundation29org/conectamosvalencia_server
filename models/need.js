'use strict'
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { conndbaccounts } = require('../db_connect')

const needSchema = new Schema({
  type: {
    type: String,
    required: true
  },
  needs: {
    type: [String],
    required: false
  },
  otherNeeds: {
    type: String,
    required: false
  },
  details: {
    type: String,
    required: false
  },
  location: {
    lat: {
      type: Number,
      required: false
    },
    lng: {
      type: Number,
      required: false
    }
  },
  status: {
    type: String,
    default: 'new'
  },
  activated: {
    type: Boolean,
    default: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  }, 
  userId: {
    type: String,
    required: true
  }
}, {
  timestamps: true // Esto añadirá automáticamente createdAt y updatedAt
});

module.exports = conndbaccounts.model('Need', needSchema);

