const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const helmet = require('helmet');
require('dotenv').config();
const Student = require("./models/Student");
const Project = require("./models/Project");
const ProjectRequest = require("./models/ProjectRequest");

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"]
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://vitcohive.com'] 
    : ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'cohive-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cohive', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Registration route
app.post("/api/register", async (req, res) => {
  try {
    const { name, regNo, email, password, year, department } = req.body;

    // Validate required fields
    if (!name || !regNo || !email || !password || !year || !department) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }

    // Validate email domain
    if (!email.endsWith('@vitstudent.ac.in')) {
      return res.status(400).json({ 
        success: false,
        error: 'Only VIT student emails are allowed' 
      });
    }

    // Validate registration number format
    if (!/^[0-9]{2}[A-Z]{3}[0-9]{4}$/.test(regNo)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid registration number format' 
      });
    }

    // Check if user already exists
    const existingStudent = await Student.findOne({ $or: [{ email }, { regNo }] });
    if (existingStudent) {
      return res.status(400).json({ 
        success: false,
        error: 'Email or registration number already registered' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new student
    const student = new Student({
      name,
      regNo,
      email,
      password: hashedPassword,
      year,
      department
    });

    await student.save();

    // Create session
    req.session.userId = student._id;
    req.session.email = student.email;
    req.session.regNo = student.regNo;
    req.session.department = student.department;
    req.session.year = student.year;

    res.status(201).json({
      success: true,
      user: {
        id: student._id,
        name: student.name,
        email: student.email,
        regNo: student.regNo,
        year: student.year,
        department: student.department
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ 
      success: false,
      error: 'Registration failed. Please try again.' 
    });
  }
});

// Login route
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required' 
      });
    }

    // Find user
    const user = await Student.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Create session
    req.session.userId = user._id;
    req.session.email = user.email;
    req.session.regNo = user.regNo;
    req.session.department = user.department;
    req.session.year = user.year;

    // Send success response
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        regNo: user.regNo,
        year: user.year,
        department: user.department
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error during login' 
    });
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ 
        success: false,
        error: 'Access denied. Authentication required' 
      });
    }

    const student = await Student.findById(req.session.userId);
    if (!student) {
      return res.status(403).json({ 
        success: false,
        error: 'Invalid session - user not found' 
      });
    }

    req.user = {
      id: student._id,
      email: student.email
    };
    next();
  } catch (err) {
    console.error("Authentication error:", err.message);
    res.status(403).json({ 
      success: false,
      error: 'Authentication failed' 
    });
  }
};

// Check session route
app.get('/api/check-session', async (req, res) => {
  if (req.session && req.session.userId) {
    try {
      const student = await Student.findById(req.session.userId);
      if (!student) {
        return res.status(401).json({ 
          success: false,
          error: 'No active session' 
        });
      }

      res.json({ 
        success: true,
        user: {
          id: student._id,
          name: student.name,
          email: student.email,
          regNo: student.regNo,
          department: student.department,
          year: student.year
        }
      });
    } catch (error) {
      console.error('Session check error:', error);
      res.status(500).json({ 
        success: false,
        error: 'Error checking session' 
      });
    }
  } else {
    res.status(401).json({ 
      success: false,
      error: 'No active session' 
    });
  }
});

// Logout route
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ 
        success: false,
        error: 'Error during logout' 
      });
    }
    
    res.clearCookie('connect.sid', {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      domain: process.env.COOKIE_DOMAIN
    });
    
    res.json({ success: true });
  });
});

// Apply authentication middleware to protected routes
app.use('/api/projects', authenticateToken);
app.use('/api/profile', authenticateToken);

// Check authentication endpoint
app.get("/api/check-auth", authenticateToken, async (req, res) => {
  try {
    const student = await Student.findById(req.user.id);
    if (!student) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      loggedIn: true,
      student: {
        id: student._id,
        name: student.name,
        email: student.email,
        regNo: student.regNo,
        year: student.year,
        department: student.department
      }
    });
  } catch (error) {
    console.error("Auth check error:", error);
    res.status(500).json({ error: "Authentication check failed" });
  }
});

// Student Profile Endpoints
app.get('/api/students/me', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findById(req.user.id);
    if (!student) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    res.json({
      success: true,
      student: {
        id: student._id,
        name: student.name,
        email: student.email,
        regNo: student.regNo,
        year: student.year,
        department: student.department,
        phone: student.phone || '',
        location: student.location || '',
        about: student.about || '',
        skills: student.skills || [],
        profilePicture: student.profilePicture || ''
      }
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to fetch profile" 
    });
  }
});

// Update student profile
app.put('/api/students/me', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findById(req.user.id);
    if (!student) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    const { name, regNo, department, year, email, phone, location, about, skills } = req.body;

    // Update fields if provided
    if (name) student.name = name;
    if (regNo) student.regNo = regNo;
    if (department) student.department = department;
    if (year) student.year = year;
    if (email) student.email = email;
    if (phone) student.phone = phone;
    if (location) student.location = location;
    if (about) student.about = about;
    if (skills) student.skills = Array.isArray(skills) ? skills : skills.split(',').map(s => s.trim()).filter(s => s);

    await student.save();

    res.json({
      success: true,
      student: {
        id: student._id,
        name: student.name,
        email: student.email,
        regNo: student.regNo,
        year: student.year,
        department: student.department,
        phone: student.phone || '',
        location: student.location || '',
        about: student.about || '',
        skills: student.skills || [],
        profilePicture: student.profilePicture || ''
      }
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to update profile" 
    });
  }
});

// Upload profile picture
app.post('/api/students/profile-picture', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findById(req.user.id);
    if (!student) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    // Generate profile picture URL
    const profilePicture = `https://ui-avatars.com/api/?name=${encodeURIComponent(student.name)}&background=6f42c1&color=fff`;

    // Update student profile picture
    student.profilePicture = profilePicture;
    await student.save();

    res.json({
      success: true,
      profilePicture
    });
  } catch (error) {
    console.error("Profile picture upload error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to upload profile picture" 
    });
  }
});

// Project Routes
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const { year, department, search } = req.query;
    const query = {};
    
    if (year) query.year = year;
    if (department) query.department = department;
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { skillsRequired: { $regex: search, $options: 'i' } }
      ];
    }

    const projects = await Project.find(query)
      .populate('creator', 'name email regNo year department')
      .populate('members', 'name email regNo year department')
      .sort({ createdAt: -1 });
      
    res.json({
      success: true,
      projects
    });
  } catch (err) {
    console.error("Projects fetch error:", err);
    res.status(500).json({ 
      success: false,
      error: "Failed to fetch projects",
      message: err.message 
    });
  }
});

// Get user's projects
app.get('/api/projects/user/:userId?', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId || req.user.id;
    
    const projects = await Project.find({
      $or: [
        { creator: userId },
        { members: userId }
      ]
    })
    .populate('creator', 'name email regNo year department')
    .populate('members', 'name email regNo year department');

    res.json({
      success: true,
      projects
    });
  } catch (error) {
    console.error('Error fetching user projects:', error);
    res.status(500).json({ error: "Failed to fetch projects" });
  }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    const { title, description, year, department, skillsRequired } = req.body;
    
    // Basic validation
    if (!title || !description || !year || !department || !skillsRequired) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }

    // Convert year to string if it's a number
    const yearString = year.toString();

    // Validate year and department against enum values
    if (!['1', '2', '3', '4'].includes(yearString)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid year. Must be 1, 2, 3, or 4'
      });
    }

    if (!['CSE', 'ECE', 'EEE', 'MECH', 'CIVIL', 'IT'].includes(department)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid department'
      });
    }

    // Ensure skillsRequired is an array
    let skillsArray;
    if (Array.isArray(skillsRequired)) {
      skillsArray = skillsRequired;
    } else if (typeof skillsRequired === 'string') {
      skillsArray = skillsRequired.split(',').map(skill => skill.trim()).filter(skill => skill);
    } else {
      skillsArray = [];
    }

    const project = new Project({
      title,
      description,
      year: yearString,
      department,
      skillsRequired: skillsArray,
      creator: req.user.id,
      members: [req.user.id],
      status: 'Open',
      progress: 0
    });

    await project.save();
    
    // Populate creator info in response
    const populatedProject = await Project.findById(project._id)
      .populate('creator', 'name email regNo year department')
      .populate('members', 'name email regNo year department');

    res.status(201).json({
      success: true,
      project: populatedProject
    });
  } catch (err) {
    console.error("Project creation error:", err);
    res.status(400).json({ 
      success: false,
      error: err.message 
    });
  }
});

app.post('/api/projects/:id/join', authenticateToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    if (project.members.includes(req.user.id)) {
      return res.status(400).json({ error: 'Already a member of this project' });
    }

    project.members.push(req.user.id);
    await project.save();
    
    res.json({
      success: true,
      message: 'Successfully joined project'
    });
  } catch (err) {
    console.error("Project join error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Get filtered projects
app.get('/api/projects/filter', authenticateToken, async (req, res) => {
  try {
    const { year, department, search } = req.query;
    
    // Build filter query
    const filter = {};
    
    // Add year filter if provided
    if (year && year !== '') {
      filter.year = year;
    }
    
    // Add department filter if provided
    if (department && department !== '') {
      filter.department = department;
    }
    
    // Add search filter if provided
    if (search && search !== '') {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { skillsRequired: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Find projects with filters
    const projects = await Project.find(filter)
      .populate('creator', 'name regNo department year')
      .populate('members', 'name regNo department year')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      projects
    });
    
  } catch (error) {
    console.error('Error filtering projects:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to filter projects',
      message: error.message
    });
  }
});

// Get project requests
app.get('/api/projects/requests', authenticateToken, async (req, res) => {
    try {
        const { projectId } = req.query;
        
        // If no projectId is provided, get all requests for projects where user is creator
        if (!projectId) {
            const userProjects = await Project.find({ creator: req.user.id });
            const projectIds = userProjects.map(p => p._id);
            
            const requests = await ProjectRequest.find({ project: { $in: projectIds } })
                .populate('project', 'title')
                .populate('student', 'name regNo')
                .sort({ createdAt: -1 });

            return res.json({
                success: true,
                requests
            });
        }

        // If projectId is provided, verify the user is either the creator or a member
        const project = await Project.findById(projectId);
        if (!project) {
            return res.status(404).json({
                success: false,
                error: 'Project not found'
            });
        }

        const isCreator = project.creator.toString() === req.user.id.toString();
        const isMember = project.members.includes(req.user.id.toString());

        if (!isCreator && !isMember) {
            return res.status(403).json({
                success: false,
                error: 'Only project members can view join requests'
            });
        }

        // Get requests for the specific project
        const requests = await ProjectRequest.find({ project: projectId })
            .populate('project', 'title')
            .populate('student', 'name regNo')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            requests
        });
    } catch (error) {
        console.error('Error fetching project requests:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch project requests'
        });
    }
});

// Get sent requests
app.get('/api/projects/requests/sent', authenticateToken, async (req, res) => {
    try {
        // Get all requests where the user is the student
        const requests = await ProjectRequest.find({ student: req.user.id })
            .populate('project', 'title creator')
            .populate('project.creator', 'name')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            requests
        });
    } catch (error) {
        console.error('Error fetching sent requests:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch sent requests'
        });
    }
});

// Delete request (for canceling)
app.delete('/api/projects/:projectId/requests/:requestId', authenticateToken, async (req, res) => {
    try {
        const { projectId, requestId } = req.params;

        // Find the request
        const request = await ProjectRequest.findById(requestId);
        if (!request) {
            return res.status(404).json({
                success: false,
                error: 'Request not found'
            });
        }

        // Verify the user is the student who sent the request
        if (request.student.toString() !== req.user.id.toString()) {
            return res.status(403).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        // Delete the request
        await request.deleteOne();

        res.json({
            success: true,
            message: 'Request deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting request:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete request'
        });
    }
});

// Get a single project by ID
app.get('/api/projects/:id', authenticateToken, async (req, res) => {
    try {
        const project = await Project.findById(req.params.id)
            .populate('creator', 'name email regNo year department')
            .populate('members', 'name email regNo year department')
            .populate('joinRequests.student', 'name email regNo year department');

        if (!project) {
            return res.status(404).json({ 
                success: false,
                error: 'Project not found' 
            });
        }

        res.json({
            success: true,
            project
        });
    } catch (error) {
        console.error('Project fetch error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch project' 
        });
    }
});

// Send join request
app.post('/api/projects/:projectId/request', authenticateToken, async (req, res) => {
  try {
    const { projectId } = req.params;
    const { message } = req.body;

    // Check if project exists
    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({
        success: false,
        error: 'Project not found'
      });
    }

    // Check if user is already a member
    if (project.members.includes(req.user.id)) {
      return res.status(400).json({
        success: false,
        error: 'You are already a member of this project'
      });
    }

    // Check if user already has a pending request
    const existingRequest = await ProjectRequest.findOne({
      project: projectId,
      student: req.user.id,
      status: 'pending'
    });

    if (existingRequest) {
      return res.status(400).json({
        success: false,
        error: 'You already have a pending request for this project'
      });
    }

    // Create new request
    const request = new ProjectRequest({
      project: projectId,
      student: req.user.id,
      message: message || '',
      status: 'pending'
    });

    await request.save();

    // Populate the request with student info
    await request.populate('student', 'name regNo');

    res.status(201).json({
      success: true,
      request
    });
  } catch (error) {
    console.error('Error creating request:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create request'
    });
  }
});

// Update request status
app.put('/api/projects/:projectId/requests/:requestId', authenticateToken, async (req, res) => {
    try {
        const { projectId, requestId } = req.params;
        const { status } = req.body;

        console.log('Updating request status:', {
            projectId,
            requestId,
            status,
            userId: req.user.id.toString()
        });

        // Validate status
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            console.log('Invalid status value:', status);
            return res.status(400).json({
                success: false,
                error: 'Invalid status'
            });
        }

        // Find the request
        const request = await ProjectRequest.findById(requestId)
            .populate('project', 'creator members')
            .populate('student', 'name regNo');

        if (!request) {
            console.log('Request not found:', requestId);
            return res.status(404).json({
                success: false,
                error: 'Request not found'
            });
        }

        // Verify project ID matches
        if (request.project._id.toString() !== projectId) {
            console.log('Project ID mismatch:', {
                requestProjectId: request.project._id.toString(),
                providedProjectId: projectId
            });
            return res.status(400).json({
                success: false,
                error: 'Project ID mismatch'
            });
        }

        // Check if user is either the project creator or the student who sent the request
        const isCreator = request.project.creator.toString() === req.user.id.toString();
        const isStudent = request.student._id.toString() === req.user.id.toString();

        console.log('Authorization check:', {
            isCreator,
            isStudent,
            projectCreator: request.project.creator.toString(),
            studentId: request.student._id.toString(),
            userId: req.user.id.toString()
        });

        if (!isCreator && !isStudent) {
            console.log('Unauthorized access attempt');
            return res.status(403).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        // If user is the student, they can only cancel (delete) their request
        if (isStudent && status !== 'pending') {
            console.log('Student trying to update status to non-pending');
            return res.status(403).json({
                success: false,
                error: 'Students can only cancel their requests'
            });
        }

        // Update request status
        request.status = status;
        await request.save();

        // If approved, add student to project members
        if (status === 'approved' && !request.project.members.includes(request.student._id)) {
            request.project.members.push(request.student._id);
            await request.project.save();
        }

        // Populate the updated request with all necessary fields
        const updatedRequest = await ProjectRequest.findById(requestId)
            .populate('project', 'title creator members')
            .populate('student', 'name regNo');

        console.log('Request updated successfully:', {
            requestId,
            newStatus: status
        });

        res.json({
            success: true,
            request: updatedRequest
        });
    } catch (error) {
        console.error('Error updating request:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update request',
            details: error.message
        });
    }
});

// Get student profile by ID
app.get('/api/students/:id', async (req, res) => {
  try {
    const student = await Student.findById(req.params.id);
    if (!student) {
      return res.status(404).json({ 
        success: false,
        error: 'Student not found' 
      });
    }

    // Check if the request is authenticated
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    let isAuthenticated = false;
    let isOwnProfile = false;

    if (token) {
      try {
        const verified = jwt.verify(token, process.env.JWT_SECRET || 'cohive-jwt-secret');
        isAuthenticated = true;
        isOwnProfile = verified.id === student._id.toString();
      } catch (err) {
        // Token is invalid, but we'll still return basic profile info
        console.error('Token verification error:', err);
      }
    }

    // Return different data based on authentication status
    const profileData = {
      id: student._id,
      name: student.name,
      email: student.email,
      regNo: student.regNo,
      year: student.year,
      department: student.department,
      profilePicture: student.profilePicture || ''
    };

    // Add additional fields only for authenticated users viewing their own profile
    if (isAuthenticated && isOwnProfile) {
      Object.assign(profileData, {
        phone: student.phone || '',
        location: student.location || '',
        about: student.about || '',
        skills: student.skills || []
      });
    }

    res.json({
      success: true,
      student: profileData
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to fetch student: " + error.message 
    });
  }
});

// Debug endpoint to check student existence
app.get('/api/debug/student/:id', async (req, res) => {
  try {
    const student = await Student.findById(req.params.id);
    if (!student) {
      return res.status(404).json({ 
        success: false,
        error: 'Student not found' 
      });
    }

    res.json({
      success: true,
      student: {
        id: student._id,
        name: student.name,
        email: student.email,
        regNo: student.regNo,
        year: student.year,
        department: student.department
      }
    });
  } catch (error) {
    console.error("Debug student fetch error:", error);
    res.status(500).json({ error: "Failed to fetch student" });
  }
});

// Update project description
app.put('/api/projects/:id', authenticateToken, async (req, res) => {
    try {
        const { description } = req.body;
        if (!description) {
            return res.status(400).json({ success: false, message: 'Description is required' });
        }

        const project = await Project.findById(req.params.id);
        if (!project) {
            return res.status(404).json({ success: false, message: 'Project not found' });
        }

        // Check if user is project creator
        if (project.creator.toString() !== req.user.id.toString()) {
            return res.status(403).json({ success: false, message: 'Only project creator can update description' });
        }

        project.description = description;
        await project.save();

        res.json({ success: true, message: 'Project description updated successfully' });
    } catch (error) {
        console.error('Error updating project description:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Add project update
app.post('/api/projects/:id/updates', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content) {
            return res.status(400).json({ 
                success: false, 
                error: 'Update content is required' 
            });
        }

        const project = await Project.findById(req.params.id);
        if (!project) {
            return res.status(404).json({ 
                success: false, 
                error: 'Project not found' 
            });
        }

        // Check if user is project creator or member
        if (project.creator.toString() !== req.user.id.toString() && !project.members.includes(req.user.id.toString())) {
            return res.status(403).json({ 
                success: false, 
                error: 'Only project members can add updates' 
            });
        }

        // Add new update
        project.updates.push({
            content: content,
            postedBy: req.user.id
        });

        await project.save();

        // Populate the update with user info
        const populatedProject = await Project.findById(project._id)
            .populate('updates.postedBy', 'name email regNo year department');

        res.json({ 
            success: true, 
            message: 'Project update added successfully',
            update: populatedProject.updates[populatedProject.updates.length - 1]
        });
    } catch (error) {
        console.error('Error adding project update:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to add project update',
            message: error.message 
        });
    }
});

// Update project progress
app.put('/api/projects/:id/progress', authenticateToken, async (req, res) => {
    try {
        const { progress, dueDate } = req.body;
        if (progress === undefined || progress < 0 || progress > 100) {
            return res.status(400).json({ success: false, message: 'Progress must be between 0 and 100' });
        }

        const project = await Project.findById(req.params.id);
        if (!project) {
            return res.status(404).json({ success: false, message: 'Project not found' });
        }

        // Check if user is project creator
        if (project.creator.toString() !== req.user.id.toString()) {
            return res.status(403).json({ success: false, message: 'Only project creator can update progress' });
        }

        project.progress = progress;
        if (dueDate) {
            project.dueDate = new Date(dueDate);
        }

        await project.save();

        res.json({ success: true, message: 'Project progress updated successfully' });
    } catch (error) {
        console.error('Error updating project progress:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Token refresh endpoint
app.post('/api/refresh-token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ 
        success: false,
        error: 'Token is required' 
      });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cohive-jwt-secret');
    const student = await Student.findById(decoded.id);
    
    if (!student) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid token - user not found' 
      });
    }

    // Generate new token
    const newToken = jwt.sign(
      { id: student._id, email: student.email },
      process.env.JWT_SECRET || 'cohive-jwt-secret',
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    res.json({
      success: true,
      token: newToken
    });
  } catch (err) {
    console.error("Token refresh error:", err);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        error: 'Token expired' 
      });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid token' 
      });
    }
    res.status(500).json({ 
      success: false,
      error: 'Token refresh failed' 
    });
  }
});

// Update project status
app.put('/api/projects/:id/status', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        const project = await Project.findById(req.params.id);
        
        if (!project) {
            return res.status(404).json({ 
                success: false,
                error: 'Project not found' 
            });
        }

        // Check if user is project creator
        if (project.creator.toString() !== req.user.id.toString()) {
            return res.status(403).json({ 
                success: false,
                error: 'Only project creator can update status' 
            });
        }

        // Validate status
        if (!['Open', 'In Progress', 'Completed', 'Closed'].includes(status)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid status value' 
            });
        }

        // Update status
        project.status = status;
        await project.save();

        res.json({ 
            success: true,
            project 
        });
    } catch (error) {
        console.error('Error updating project status:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to update project status' 
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false,
    error: 'Something went wrong!' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});