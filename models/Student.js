const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  regNo: {
    type: String,
    required: true,
    unique: true,
    match: /^[0-9]{2}[A-Z]{3}[0-9]{4}$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: /^[a-zA-Z0-9.]+@vitstudent\.ac\.in$/
  },
  password: {
    type: String,
    required: true,
    minlength: [6, 'Password must be at least 6 characters long']
  },
  year: {
    type: Number,
    required: true,
    min: 1,
    max: 4
  },
  department: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    match: /^[0-9]{10}$/,
    default: ''
  },
  location: {
    type: String,
    default: ''
  },
  about: {
    type: String,
    default: ''
  },
  skills: {
    type: [String],
    default: []
  },
  profilePicture: {
    type: String,
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Student', studentSchema);