const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'Veuillez fournir votre prénom'],
        trim: true,
        maxLength: [50, 'Le prénom ne peut pas dépasser 50 caractères']
    },
    lastName: {
        type: String,
        required: [true, 'Veuillez fournir votre nom'],
        trim: true,
        maxLength: [50, 'Le nom ne peut pas dépasser 50 caractères']
    },
    email: {
        type: String,
        required: [true, 'Veuillez fournir votre email'],
        unique: true,
        lowercase: true,
        match: [
            /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/,
            'Veuillez fournir un email valide'
        ]
    },
    password: {
        type: String,
        required: [true, 'Veuillez fournir un mot de passe'],
        minlength: [8, 'Le mot de passe doit contenir au moins 8 caractères'],
        select: false // Don't return password in queries
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user'
    },
    verified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationExpires: Date,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    passwordChangedAt: Date,
    sessionToken: String,
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    trustedDevices: [String],
    twoFactorSecret: String,
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    subscription: {
        type: {
            type: String,
            enum: ['free', 'basic', 'premium', 'ultimate'],
            default: 'free'
        },
        startDate: Date,
        endDate: Date,
        status: {
            type: String,
            enum: ['active', 'expired', 'cancelled'],
            default: 'active'
        }
    },
    library: [{
        book: {
            type: mongoose.Schema.ObjectId,
            ref: 'Book'
        },
        purchaseDate: Date,
        lastAccessed: Date,
        progress: Number
    }],
    activityLog: [{
        action: String,
        path: String,
        timestamp: Date,
        ip: String
    }],
    preferences: {
        language: {
            type: String,
            default: 'fr'
        },
        emailNotifications: {
            type: Boolean,
            default: true
        },
        theme: {
            type: String,
            enum: ['light', 'dark'],
            default: 'light'
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: Date
}, {
    timestamps: true
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        // Generate salt
        const salt = await bcrypt.genSalt(12);
        // Hash password
        this.password = await bcrypt.hash(this.password, salt);
        
        // Update passwordChangedAt field
        this.passwordChangedAt = Date.now() - 1000;
        
        next();
    } catch (err) {
        next(err);
    }
});

// Method to check if password matches
userSchema.methods.matchPassword = async function(enteredPassword) {
    try {
        return await bcrypt.compare(enteredPassword, this.password);
    } catch (err) {
        throw new Error(err);
    }
};

// Method to generate verification token
userSchema.methods.generateVerificationToken = function() {
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    this.verificationToken = crypto
        .createHash('sha256')
        .update(verificationToken)
        .digest('hex');
    
    this.verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    
    return verificationToken;
};

// Method to generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    this.resetPasswordToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    
    this.resetPasswordExpires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour
    
    return resetToken;
};

// Method to generate session token
userSchema.methods.generateSessionToken = function() {
    this.sessionToken = crypto.randomBytes(32).toString('hex');
    return this.sessionToken;
};

// Method to check if user account is locked
userSchema.methods.isLocked = function() {
    return this.lockUntil && this.lockUntil > Date.now();
};

// Method to increment login attempts
userSchema.methods.incrementLoginAttempts = async function() {
    // If lock has expired, reset attempts and lock
    if (this.lockUntil && this.lockUntil < Date.now()) {
        this.loginAttempts = 1;
        this.lockUntil = undefined;
        await this.save();
        return;
    }

    // Increment attempts
    this.loginAttempts += 1;

    // Lock account if max attempts reached
    if (this.loginAttempts >= 5) {
        this.lockUntil = Date.now() + 60 * 60 * 1000; // 1 hour
    }

    await this.save();
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
    this.loginAttempts = 0;
    this.lockUntil = undefined;
    await this.save();
};

// Method to add trusted device
userSchema.methods.addTrustedDevice = async function(deviceId) {
    if (!this.trustedDevices.includes(deviceId)) {
        this.trustedDevices.push(deviceId);
        await this.save();
    }
};

// Method to remove trusted device
userSchema.methods.removeTrustedDevice = async function(deviceId) {
    this.trustedDevices = this.trustedDevices.filter(id => id !== deviceId);
    await this.save();
};

// Method to check subscription status
userSchema.methods.hasValidSubscription = function() {
    return this.subscription.status === 'active' && 
           this.subscription.endDate > Date.now();
};

// Virtual for full name
userSchema.virtual('fullName').get(function() {
    return `${this.firstName} ${this.lastName}`;
});

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ verificationToken: 1 });
userSchema.index({ resetPasswordToken: 1 });

const User = mongoose.model('User', userSchema);

module.exports = User;
