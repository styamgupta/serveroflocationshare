require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

// Initialize Express app
const app = express();
const server = http.createServer(app);
app.use(express.json());
// Enhanced Socket.IO configuration
const io = socketIo(server, {
    cors: {
        origin: process.env.CLIENT_URL || "https://clientoflocationshare.vercel.app",
        methods: ["GET", "POST"],
        credentials: true
    },
    pingTimeout: 60000,
    pingInterval: 25000
});

// Security middleware
app.use(cors({
    origin: process.env.CLIENT_URL || "https://clientoflocationshare.vercel.app",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});

// Apply rate limiting to all API routes
app.use('/api/', apiLimiter);

// MongoDB connection with enhanced error handling
const connectWithRetry = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://satyamguptasg1234asd:Satyam%402024@cluster0.ugfa9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            retryWrites: true,
            w: 'majority'
        });
        console.log("MongoDB connected successfully");
    } catch (err) {
        console.error("MongoDB connection error:", err);
        // Retry after 5 seconds
        setTimeout(connectWithRetry, 5000);
    }
};

connectWithRetry();

// User Schema with enhanced validation
const userSchema = new mongoose.Schema({
    mobile: {
        type: String,
        required: [true, 'Mobile number is required'],
        unique: true,
        validate: {
            validator: function (v) {
                return /^\d{10}$/.test(v);
            },
            message: props => `${props.value} is not a valid mobile number!`
        }
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long'],
        select: false
    },
    userType: {
        type: String,
        enum: {
            values: ['user', 'driver'],
            message: 'User type must be either "user" or "driver"'
        },
        required: [true, 'User type is required']
    },
    currentLocation: {
        type: {
            lat: { 
                type: Number, 
                min: [-90, 'Latitude must be between -90 and 90'], 
                max: [90, 'Latitude must be between -90 and 90'] 
            },
            lng: { 
                type: Number, 
                min: [-180, 'Longitude must be between -180 and 180'], 
                max: [180, 'Longitude must be between -180 and 180'] 
            }
        },
        validate: {
            validator: function(loc) {
                if (!loc) return true;
                return loc.lat >= -90 && loc.lat <= 90 && loc.lng >= -180 && loc.lng <= 180;
            },
            message: 'Invalid coordinates'
        }
    },
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        maxlength: [50, 'Name cannot be longer than 50 characters']
    },
    vehicleNumber: {
        type: String,
        default: '',
        validate: {
            validator: function (v) {
                return this.userType === 'driver' ? v && v.length > 0 : true;
            },
            message: 'Vehicle number is required for drivers'
        }
    },
    isSharingLocation: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true,
    toJSON: {
        transform: function (doc, ret) {
            delete ret.password;
            return ret;
        }
    }
});

const UsersData = mongoose.model('UsersData', userSchema);

// Enhanced authentication middleware
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Authentication token required'
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '123sec');

        if (!decoded._id || !decoded.mobile) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token payload'
            });
        }

        const user = await UsersData.findOne({
            _id: decoded._id,
            mobile: decoded.mobile
        }).select('-password');

        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'User not found'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'Token expired'
            });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }
        res.status(401).json({
            success: false,
            error: 'Authentication failed'
        });
    }
};

// API Routes with enhanced validation and error handling

// User registration with validation
app.post('/api/register', [
    body('mobile').trim().isLength({ min: 10, max: 10 }).withMessage('Mobile must be 10 digits').isNumeric(),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('userType').isIn(['user', 'driver']).withMessage('Invalid user type'),
    body('name').trim().notEmpty().withMessage('Name is required').isLength({ max: 50 }).withMessage('Name too long'),
    body('vehicleNumber').if(body('userType').equals('driver')).notEmpty().withMessage('Vehicle number is required for drivers')
], async (req, res) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(err => err.msg)
            });
        }

        const { mobile, password, userType, name, vehicleNumber } = req.body;

        // Check if user already exists (this helps with user experience)
        const existingUser = await UsersData.findOne({ mobile });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Mobile number already registered'
            });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new UsersData({
            mobile,
            password: hashedPassword,
            userType,
            name,
            ...(userType === 'driver' && { vehicleNumber })
        });

        await user.save();

        const token = jwt.sign(
            { _id: user._id, mobile: user.mobile, userType: user.userType },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        return res.status(201).json({
            success: true,
            user: {
                _id: user._id,
                mobile: user.mobile,
                userType: user.userType,
                name: user.name,
                ...(userType === 'driver' && { vehicleNumber: user.vehicleNumber })
            },
            token
        });

    } catch (error) {
        console.error('Register error:', error);
        
        // Handle specific errors
        if (error.name === 'MongoError' && error.code === 11000) {
            return res.status(409).json({
                success: false,
                error: 'Mobile number already registered'
            });
        }
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                error: error.message
            });
        }

        return res.status(500).json({
            success: false,
            error: 'Server error during registration'
        });
    }
});

// User login with validation
app.post('/api/login', [
    body('mobile').trim().notEmpty().withMessage('Mobile is required'),
    body('password').notEmpty().withMessage('Password is required'),
    body('userType').isIn(['user', 'driver']).withMessage('Invalid user type')
], async (req, res) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(err => err.msg)
            });
        }
        
        const { mobile, password, userType } = req.body;
        
        const user = await UsersData.findOne({ mobile, userType });
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        console.log(password, user.password);
        
        if (!password) {
            return res.status(400).json({ error: "Password is required" });
          }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        const token = jwt.sign(
            {
                _id: user._id,
                mobile: user.mobile,
                userType: user.userType,
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        return res.status(200).json({
            success: true,
            user: {
                _id: user._id,
                mobile: user.mobile,
                userType: user.userType,
                name: user.name,
                currentLocation: user.currentLocation,
                isSharingLocation: user.isSharingLocation,
                ...(user.userType === 'driver' && { vehicleNumber: user.vehicleNumber }),
            },
            token,
        });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({
            success: false,
            error: 'Server error during login'
        });
    }
});

// Verify token
app.get('/api/verify', authenticate, (req, res) => {
    res.json({ 
        success: true,
        user: req.user 
    });
});

// Get all drivers with pagination
app.get('/api/drivers', authenticate, [
    body('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    body('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
    try {
        if (req.user.userType !== 'user') {
            return res.status(403).json({
                success: false,
                error: 'Only users can access this endpoint'
            });
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(err => err.msg)
            });
        }

        const { page = 1, limit = 10 } = req.query;
        const skip = (page - 1) * limit;

        const drivers = await UsersData.find(
            { userType: 'driver', isSharingLocation: true },
            { _id: 1, name: 1, currentLocation: 1, vehicleNumber: 1, isSharingLocation: 1 }
        )
            .skip(skip)
            .limit(parseInt(limit));

        const total = await UsersData.countDocuments({ userType: 'driver', isSharingLocation: true });

        res.json({
            success: true,
            data: drivers,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get drivers error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error while fetching drivers'
        });
    }
});

// Update location with validation
app.post('/api/update-location', authenticate, [
    body('lat').isFloat({ min: -90, max: 90 }).withMessage('Latitude must be between -90 and 90'),
    body('lng').isFloat({ min: -180, max: 180 }).withMessage('Longitude must be between -180 and 180')
], async (req, res) => {
    try {
        if (req.user.userType !== 'driver') {
            return res.status(403).json({
                success: false,
                error: 'Only drivers can update location'
            });
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(err => err.msg)
            });
        }

        const { lat, lng } = req.body;

        const user = await UsersData.findByIdAndUpdate(
            req.user._id,
            {
                currentLocation: { lat, lng },
                isSharingLocation: true
            },
            { new: true, select: '-password' }
        );

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        io.to('users').emit('locationUpdate', {
            userId: user._id,
            location: user.currentLocation,
            name: user.name,
            vehicleNumber: user.vehicleNumber,
            timestamp: new Date()
        });

        res.json({
            success: true,
            message: 'Location updated successfully',
            location: user.currentLocation
        });
    } catch (error) {
        console.error('Update location error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error while updating location'
        });
    }
});

// Stop sharing location
app.post('/api/stop-sharing', authenticate, async (req, res) => {
    try {
        if (req.user.userType !== 'driver') {
            return res.status(403).json({
                success: false,
                error: 'Only drivers can stop sharing location'
            });
        }

        const user = await UsersData.findByIdAndUpdate(
            req.user._id,
            {
                isSharingLocation: false,
                currentLocation: null
            },
            { new: true, select: '-password' }
        );

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        io.to('users').emit('driverStoppedSharing', {
            userId: user._id
        });

        res.json({
            success: true,
            message: 'Location sharing stopped'
        });
    } catch (error) {
        console.error('Stop sharing error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error while stopping location sharing'
        });
    }
});

// Get user profile
app.get('/api/profile', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            data: {
                _id: req.user._id,
                mobile: req.user.mobile,
                userType: req.user.userType,
                name: req.user.name,
                currentLocation: req.user.currentLocation,
                vehicleNumber: req.user.vehicleNumber || null,
                isSharingLocation: req.user.isSharingLocation,
                createdAt: req.user.createdAt
            }
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error while fetching profile'
        });
    }
});

// Enhanced Socket.IO logic with error handling
io.on('connection', (socket) => {
    console.log(`New client connected: ${socket.id}`);

    socket.on('join', async ({ userId, userType, token }, callback) => {
        try {
            if (!userId || !userType || !token) {
                throw new Error('Missing required fields');
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
            const user = await UsersData.findById(decoded._id);

            if (!user) {
                throw new Error('User not found');
            }

            if (decoded._id !== userId) {
                throw new Error('Unauthorized');
            }

            socket.join(userType === 'driver' ? 'drivers' : 'users');
            socket.userId = userId;
            console.log(`${userId} (${user.name}) joined as ${userType}`);

            if (userType === 'driver' && user.currentLocation && user.isSharingLocation) {
                io.to('users').emit('locationUpdate', {
                    userId: user._id,
                    location: user.currentLocation,
                    name: user.name,
                    vehicleNumber: user.vehicleNumber,
                    timestamp: new Date()
                });
            }

            if (typeof callback === 'function') {
                callback({ status: 'success' });
            }
        } catch (error) {
            console.error('Socket join error:', error.message);
            if (typeof callback === 'function') {
                callback({ status: 'error', message: error.message });
            }
            socket.disconnect();
        }
    });

    socket.on('updateLocation', async ({ userId, location, token }, callback) => {
        try {
            if (!userId || !location || !token) {
                throw new Error('Missing required fields');
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded._id !== userId) {
                throw new Error('Unauthorized');
            }

            const user = await UsersData.findByIdAndUpdate(
                userId,
                {
                    currentLocation: location,
                    isSharingLocation: true
                },
                { new: true }
            );

            if (!user) {
                throw new Error('User not found');
            }

            if (user.userType === 'driver') {
                io.to('users').emit('locationUpdate', {
                    userId: user._id,
                    location: user.currentLocation,
                    name: user.name,
                    vehicleNumber: user.vehicleNumber,
                    timestamp: new Date()
                });
            }

            if (typeof callback === 'function') {
                callback({ status: 'success' });
            }
        } catch (error) {
            console.error('Update location socket error:', error.message);
            if (typeof callback === 'function') {
                callback({ status: 'error', message: error.message });
            }
        }
    });

    socket.on('stopSharing', async ({ userId, token }, callback) => {
        try {
            if (!userId || !token) {
                throw new Error('Missing required fields');
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded._id !== userId) {
                throw new Error('Unauthorized');
            }

            const user = await UsersData.findByIdAndUpdate(
                userId,
                {
                    isSharingLocation: false,
                    currentLocation: null
                },
                { new: true }
            );

            if (!user) {
                throw new Error('User not found');
            }

            io.to('users').emit('driverStoppedSharing', {
                userId: user._id
            });

            if (typeof callback === 'function') {
                callback({ status: 'success' });
            }
        } catch (error) {
            console.error('Stop sharing socket error:', error.message);
            if (typeof callback === 'function') {
                callback({ status: 'error', message: error.message });
            }
        }
    });

    socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`);
        if (socket.rooms.has('drivers') && socket.userId) {
            io.to('users').emit('driverStoppedSharing', { userId: socket.userId });
        }
    });

    socket.on('error', (error) => {
        console.error(`Socket error for ${socket.id}:`, error);
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', err.stack);
    
    // Handle mongoose validation errors
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: Object.values(err.errors).map(e => e.message)
        });
    }
    
    // Handle JWT errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            error: 'Invalid token'
        });
    }
    
    // Handle rate limit errors
    if (err.name === 'RateLimitError') {
        return res.status(429).json({
            success: false,
            error: 'Too many requests, please try again later'
        });
    }

    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});