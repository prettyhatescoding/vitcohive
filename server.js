require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const auth = require('./middleware/auth');

// Import models
const Student = require('./models/Student');
const Project = require('./models/Project');

// Initialize express app
const app = express();

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'cohive-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cohive', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000'],
  credentials: true
}));

// Serve static files
app.use(express.static('public'));

// Auth routes
app.get('/auth/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/auth/login.html'));
});

app.get('/auth/signup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/auth/signup.html'));
});

// Check authentication status
app.get('/api/check-auth', auth, async (req, res) => {
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
      loggedIn: true,
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
    console.error('Auth check error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Authentication check failed' 
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
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
    });
    
    res.json({ success: true });
  });
});

// Apply auth middleware to protected routes
app.use('/api/projects', auth);
app.use('/api/profile', auth);

// Define routes for HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

// Serve project page with authentication
app.get('/project', auth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/project.html'));
});

// Student Registration
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { name, regNo, email, password, year, department } = req.body;

    // Validate required fields
    if (!name || !regNo || !email || !password || !year || !department) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }

    // Validate email format
    const emailRegex = /^[a-zA-Z0-9.]+@vitstudent\.ac\.in$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid email format. Must be a VIT student email' 
      });
    }

    // Validate registration number format
    const regNoRegex = /^[0-9]{2}[A-Z]{3}[0-9]{4}$/;
    if (!regNoRegex.test(regNo)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid registration number format' 
      });
    }

    // Check if student exists
    const existingStudent = await Student.findOne({ $or: [{ email }, { regNo }] });
    if (existingStudent) {
      return res.status(400).json({ 
        success: false,
        error: 'Student already exists with this email or registration number' 
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

    // Generate token
    const token = jwt.sign(
      { userId: student._id, email: student.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      token,
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
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Registration failed: ' + error.message 
    });
  }
});

// Student Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required' 
      });
    }

    // 2. Find student (case insensitive search)
    const student = await Student.findOne({ 
      email: { $regex: new RegExp(email, 'i') } 
    });
    
    if (!student) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // 3. Verify password
    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // 4. Generate token
    const token = jwt.sign(
      { 
        userId: student._id, 
        email: student.email
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 5. Send response
    res.json({
      success: true,
      token,
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
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false,
      error: 'Login failed. Please try again.' 
    });
  }
});

// Project Endpoints

// Create Project
app.post('/api/projects', auth, async (req, res) => {
  try {
    const { title, description, year, department, skills } = req.body;

    const project = new Project({
      title,
      description,
      year,
      department,
      skillsRequired: skills,
      creator: req.student._id,
      members: [req.student._id] // Creator is automatically a member
    });

    await project.save();

    res.status(201).json({
      success: true,
      project
    });
  } catch (error) {
    console.error('Project creation error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Project creation failed' 
    });
  }
});

// Get All Projects
app.get('/api/projects', auth, async (req, res) => {
  try {
    const projects = await Project.find()
      .populate('creator', 'name email regNo year department')
      .populate('members', 'name email regNo year department');

    res.json({
      success: true,
      projects
    });
  } catch (error) {
    console.error('Projects fetch error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch projects' 
    });
  }
});

// Get filtered projects
app.get('/api/projects/filter', auth, async (req, res) => {
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
      .sort({ createdAt: -1 })
      .lean();
    
    // Format response
    const formattedProjects = projects.map(project => {
      // Ensure all required fields exist
      const formattedProject = {
        _id: project._id,
        title: project.title || 'Untitled Project',
        description: project.description || 'No description available',
        year: project.year || 'N/A',
        department: project.department || 'N/A',
        skillsRequired: project.skillsRequired || [],
        status: project.status || 'Open',
        progress: project.progress || 0,
        createdAt: project.createdAt || new Date()
      };

      // Format creator if exists
      if (project.creator) {
        formattedProject.creator = {
          name: project.creator.name || 'Unknown',
          regNo: project.creator.regNo || 'N/A',
          department: project.creator.department || 'N/A',
          year: project.creator.year || 'N/A'
        };
      }

      // Format members if exists
      if (project.members && Array.isArray(project.members)) {
        formattedProject.members = project.members.map(member => ({
          name: member.name || 'Unknown',
          regNo: member.regNo || 'N/A',
          department: member.department || 'N/A',
          year: member.year || 'N/A'
        }));
      } else {
        formattedProject.members = [];
      }

      return formattedProject;
    });
    
    res.json({
      success: true,
      projects: formattedProjects
    });
    
  } catch (error) {
    console.error('Error filtering projects:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to filter projects',
      message: error.message,
      details: error.stack
    });
  }
});

// Get Single Project
app.get('/api/projects/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate('creator', 'name email regNo year department')
      .populate('members', 'name email regNo year department');

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

// Join Project
app.post('/api/projects/:id/join', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ 
        success: false,
        error: 'Project not found' 
      });
    }

    // Check if already a member
    if (project.members.includes(req.student._id)) {
      return res.status(400).json({ 
        success: false,
        error: 'Already a member of this project' 
      });
    }

    project.members.push(req.student._id);
    await project.save();

    res.json({
      success: true,
      message: 'Successfully joined project'
    });
  } catch (error) {
    console.error('Join project error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to join project' 
    });
  }
});

// Student Profile
app.get('/api/students/me', auth, async (req, res) => {
  try {
    res.json({
      success: true,
      student: req.student
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch profile' 
    });
  }
});

// Get all users (for admin)
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await Student.find({}, { password: 0 });
    res.json(users);
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch users' 
    });
  }
});

// List all users (for debugging)
app.get('/api/debug/users', async (req, res) => {
  try {
    const users = await Student.find({}, { password: 0 });
    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Debug users fetch error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch users' 
    });
  }
});

// Update profile
app.put('/api/profile', auth, async (req, res) => {
  try {
    const { name, department, year, email, phone, location, about, skills } = req.body;

    // Find and update student
    const student = await Student.findByIdAndUpdate(
      req.student._id,
      {
        name,
        department,
        year,
        email,
        phone,
        location,
        about,
        skills
      },
      { new: true } // Return updated document
    );

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
        department: student.department,
        phone: student.phone,
        location: student.location,
        about: student.about,
        skills: student.skills
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile'
    });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});