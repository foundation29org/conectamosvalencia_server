'use strict'
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { conndbaccounts } = require('../db_connect')

const validNeedTypes = [
  'all',
  'transport_logistics',
  'humanitarian_aid',
  'professional_services',
  'construction_repair',
  'technical_services',
  'volunteering',
  'financial_support',
  'equipment_supplies',
  'health_services',
  'storage',
  'vehicles',
  'animal_resources',
  'education_training',
  'communication_technology',
  'temporary_infrastructure',
  'children_families',
  'disability_support',
  'psychosocial_support',
  'energy_supply',
  'environmental_recovery',
  'other'
];

const needSchema = new Schema({
  type: {
    type: String,
    required: true
  },
  needs: {
    type: [String],
    required: false,
    validate: {
      validator: function(array) {
          return array.every(item => validNeedTypes.includes(item));
      },
      message: 'Uno o más tipos de necesidad no son válidos'
    }
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

