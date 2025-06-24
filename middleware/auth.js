const jwt = require('jsonwebtoken');
const Student = require('../models/Student');

const auth = async (req, res, next) => {
  try {
    // First check session
    if (req.session && req.session.userId) {
      const student = await Student.findById(req.session.userId);
      if (!student) {
        return res.status(401).json({ 
          success: false,
          error: 'Session invalid - user not found' 
        });
      }
      req.user = {
        id: student._id,
        email: student.email
      };
      return next();
    }

    // Then check JWT token
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ 
        success: false,
        error: 'No authentication token provided' 
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cohive-jwt-secret');
      const student = await Student.findById(decoded.id);
      
      if (!student) {
        return res.status(401).json({ 
          success: false,
          error: 'Token invalid - user not found' 
        });
      }

      // Create session
      req.session.userId = student._id;
      req.session.email = student.email;
      req.session.regNo = student.regNo;
      req.session.department = student.department;
      req.session.year = student.year;

      req.user = decoded;
      next();
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid token' 
        });
      }
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          success: false,
          error: 'Token expired' 
        });
      }
      throw error;
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error during authentication' 
    });
  }
};

module.exports = auth; 