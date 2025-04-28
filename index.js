require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();
const server = http.createServer(app);

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

// Middleware setup
app.use(cors({
    origin: process.env.CLIENT_URL || "https://clientoflocationshare.vercel.app/",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB connection
console.log(process.env.MONGODB_URI);

mongoose.connect(process.env.MONGODB_URI || 'MONGO_URI=mongodb+srv://satyamguptasg1234asd:Satyam%402024@cluster0.ugfa9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    // useNewUrlParser: true,
    // useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
})
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err => {
        console.error("MongoDB connection error:", err);
        process.exit(1);
    });

// User Schema
const userSchema = new mongoose.Schema({
    mobile: {
        type: String,
        required: true,
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
        required: true,
        minlength: 6
    },
    userType: {
        type: String,
        enum: ['user', 'driver'],
        required: true
    },
    currentLocation: {
        lat: { type: Number, min: -90, max: 90 },
        lng: { type: Number, min: -180, max: 180 }
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    vehicleNumber: {
        type: String,
        default: '',
        validate: {
            validator: function (v) {
                return this.userType === 'driver' ? v.length > 0 : true;
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

const User = mongoose.model('User', userSchema);

// Authentication middleware
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

        const user = await User.findOne({
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
        res.status(401).json({
            success: false,
            error: 'Please authenticate with a valid token'
        });
    }
};

// API Routes

// User registration
app.post('/api/register', async (req, res) => {
    try {
        const { mobile, password, userType, name, vehicleNumber } = req.body;

        if (!mobile || !password || !userType || !name) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields'
            });
        }

        if (userType === 'driver' && !vehicleNumber) {
            return res.status(400).json({
                success: false,
                error: 'Vehicle number is required for drivers'
            });
        }

        const existingUser = await User.findOne({ mobile });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Mobile number already registered'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
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

        res.status(201).json({
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
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { mobile, password, userType } = req.body;

        if (!mobile || !password || !userType) {
            return res.status(400).json({
                success: false,
                error: 'Mobile, password and userType are required'
            });
        }

        const user = await User.findOne({ mobile, userType });
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        const token = jwt.sign(
            { _id: user._id, mobile: user.mobile, userType: user.userType },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            user: {
                _id: user._id,
                mobile: user.mobile,
                userType: user.userType,
                name: user.name,
                currentLocation: user.currentLocation,
                isSharingLocation: user.isSharingLocation,
                ...(user.userType === 'driver' && { vehicleNumber: user.vehicleNumber })
            },
            token
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Verify token
app.get('/api/verify', authenticate, (req, res) => {
    res.send({ user: req.user });
});

// Get all drivers
app.get('/api/drivers', authenticate, async (req, res) => {
    try {
        if (req.user.userType !== 'user') {
            return res.status(403).json({
                success: false,
                error: 'Only users can access this endpoint'
            });
        }

        const { page = 1, limit = 10 } = req.query;
        const skip = (page - 1) * limit;

        const drivers = await User.find(
            { userType: 'driver' },
            { _id: 1, name: 1, currentLocation: 1, vehicleNumber: 1, isSharingLocation: 1 }
        )
            .skip(skip)
            .limit(parseInt(limit));

        const total = await User.countDocuments({ userType: 'driver' });

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
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Update location
app.post('/api/update-location', authenticate, async (req, res) => {
    try {
        if (req.user.userType !== 'driver') {
            return res.status(403).json({
                success: false,
                error: 'Only drivers can update location'
            });
        }

        const { lat, lng } = req.body;
        if (lat === undefined || lng === undefined) {
            return res.status(400).json({
                success: false,
                error: 'Latitude and longitude are required'
            });
        }

        if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
            return res.status(400).json({
                success: false,
                error: 'Invalid coordinates'
            });
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { 
                currentLocation: { lat, lng },
                isSharingLocation: true
            },
            { new: true, select: '-password' }
        );

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
        res.status(500).json({
            success: false,
            error: error.message
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

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { 
                isSharingLocation: false,
                currentLocation: null
            },
            { new: true, select: '-password' }
        );

        io.to('users').emit('driverStoppedSharing', {
            userId: user._id
        });

        res.json({
            success: true,
            message: 'Location sharing stopped'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
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
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Socket.IO logic
io.on('connection', (socket) => {
    console.log(`New client connected: ${socket.id}`);

    socket.on('join', async ({ userId, userType, token }) => {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
            const user = await User.findById(decoded._id);

            if (!user) {
                socket.disconnect();
                return;
            }

            socket.join(userType === 'driver' ? 'drivers' : 'users');
            socket.userId = userId; // Store userId for later use
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
        } catch (error) {
            console.error('Socket authentication error:', error);
            socket.disconnect();
        }
    });

    socket.on('updateLocation', async ({ userId, location, token }) => {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded._id !== userId) {
                throw new Error('Unauthorized');
            }

            const user = await User.findByIdAndUpdate(
                userId,
                { 
                    currentLocation: location,
                    isSharingLocation: true
                },
                { new: true }
            );

            if (user && user.userType === 'driver') {
                io.to('users').emit('locationUpdate', {
                    userId: user._id,
                    location: user.currentLocation,
                    name: user.name,
                    vehicleNumber: user.vehicleNumber,
                    timestamp: new Date()
                });
            }
        } catch (error) {
            console.error('Error updating location:', error);
        }
    });

    socket.on('stopSharing', async ({ userId, token }) => {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded._id !== userId) {
                throw new Error('Unauthorized');
            }

            const user = await User.findByIdAndUpdate(
                userId,
                { 
                    isSharingLocation: false,
                    currentLocation: null
                },
                { new: true }
            );

            io.to('users').emit('driverStoppedSharing', {
                userId: user._id
            });
        } catch (error) {
            console.error('Error stopping location sharing:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`);
        if (socket.rooms.has('drivers') && socket.userId) {
            io.to('users').emit('driverStoppedSharing', { userId: socket.userId });
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
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