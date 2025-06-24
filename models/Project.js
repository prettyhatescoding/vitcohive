const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  year: {
    type: String,
    required: true,
    enum: ['1', '2', '3', '4']
  },
  department: {
    type: String,
    required: true,
    enum: ['CSE', 'ECE', 'EEE', 'MECH', 'CIVIL', 'IT']
  },
  skillsRequired: [{
    type: String,
    trim: true
  }],
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Student',
    required: true
  },
  members: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Student'
  }],
  status: {
    type: String,
    enum: ['Open', 'In Progress', 'Completed', 'Closed'],
    default: 'Open'
  },
  progress: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  updates: [{
    content: {
      type: String,
      required: true,
      trim: true
    },
    postedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Student',
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  joinRequests: [{
    student: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Student',
      required: true
    },
    status: {
      type: String,
      enum: ['Pending', 'Accepted', 'Rejected'],
      default: 'Pending'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

// Indexes for better query performance
projectSchema.index({ title: 'text', description: 'text', skillsRequired: 'text' });
projectSchema.index({ year: 1, department: 1 });
projectSchema.index({ status: 1 });
projectSchema.index({ creator: 1 });
projectSchema.index({ members: 1 });

const Project = mongoose.model('Project', projectSchema);

module.exports = Project;