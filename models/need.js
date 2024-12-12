'use strict'
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { conndbaccounts } = require('../db_connect')

const needSchema = new Schema({
  institution: {
    type: String,
    required: true
  },
  personalInfo: {
    fullName: { type: String, required: true },
    idType: { type: String, required: true },
    idNumber: { type: String, required: true },
    lostDocumentation: { type: Boolean, default: false },
    birthDate: { type: Date, required: true },
    gender: { type: String, required: true },
    language: { type: String, required: true },
    residence: { type: String, required: true },
    city: { type: String, required: true },
    householdMembers: { type: Number, required: true, min: 1 },
    phone: { type: String, required: true, match: /^[+]?[0-9]{9,15}$/ }
  },
  housing: {
    items: {
      noHousing: { type: Boolean, default: false },
      housingDeficiencies: { type: Boolean, default: false },
      unsanitary: { type: Boolean, default: false },
      overcrowding: { type: Boolean, default: false },
      noBasicGoods: { type: Boolean, default: false },
      foodShortage: { type: Boolean, default: false }
    },
    observations: { type: String }
  },
  employment: {
    items: {
      allUnemployed: { type: Boolean, default: false },
      jobLoss: { type: Boolean, default: false },
      temporaryLayoff: { type: Boolean, default: false },
      precariousEmployment: { type: Boolean, default: false }
    },
    observations: { type: String }
  },
  socialNetworks: {
    items: {
      socialIsolation: { type: Boolean, default: false },
      neighborConflicts: { type: Boolean, default: false },
      needsInstitutionalSupport: { type: Boolean, default: false },
      vulnerableMinors: { type: Boolean, default: false }
    },
    observations: { type: String }
  },
  publicServices: {
    items: {
      noHealthCoverage: { type: Boolean, default: false },
      discontinuedMedicalTreatment: { type: Boolean, default: false },
      unschooledMinors: { type: Boolean, default: false },
      dependencyWithoutAssessment: { type: Boolean, default: false },
      mentalHealthIssues: { type: Boolean, default: false }
    },
    observations: { type: String }
  },
  socialParticipation: {
    items: {
      memberOfOrganizations: { type: Boolean, default: false },
      receivesSocialServices: { type: Boolean, default: false }
    },
    observations: { type: String }
  },
  economicCoverage: {
    items: {
      noIncome: { type: Boolean, default: false },
      pensionsOrBenefits: { type: Boolean, default: false },
      receivesRviImv: { type: Boolean, default: false }
    },
    observations: { type: String }
  },
  details: { type: String },
  location: {
    lat: { type: Number, required: true },
    lng: { type: Number, required: true }
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

