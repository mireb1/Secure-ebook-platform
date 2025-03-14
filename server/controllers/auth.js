const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const sendEmail = require('../utils/sendEmail');

// Helper function to generate tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE || '1h'
    });

    const refreshToken = jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d'
    });

    return { accessToken, refreshToken };
};

// Helper function to set secure cookies
const setTokenCookies = (res, accessToken, refreshToken) => {
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    };

    res.cookie('token', accessToken, {
        ...cookieOptions,
        expires: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
    });

    res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    });
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { firstName, lastName, email, password } = req.body;

        // Check if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({
                error: 'Un utilisateur avec cet email existe déjà'
            });
        }

        // Create verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        // Create user
        user = await User.create({
            firstName,
            lastName,
            email,
            password,
            verificationToken: crypto
                .createHash('sha256')
                .update(verificationToken)
                .digest('hex'),
            verificationExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
        });

        // Send verification email
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
        await sendEmail({
            email: user.email,
            subject: 'Vérification de votre compte',
            template: 'emailVerification',
            context: {
                name: user.firstName,
                url: verificationUrl
            }
        });

        res.status(201).json({
            success: true,
            message: 'Inscription réussie. Veuillez vérifier votre email.'
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({
            error: 'Erreur lors de l\'inscription'
        });
    }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        // Check if user exists
        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            return res.status(401).json({
                error: 'Email ou mot de passe incorrect'
            });
        }

        // Check if account is locked
        if (user.isLocked()) {
            return res.status(401).json({
                error: 'Compte temporairement bloqué. Veuillez réessayer plus tard.'
            });
        }

        // Check if password matches
        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            await user.incrementLoginAttempts();
            return res.status(401).json({
                error: 'Email ou mot de passe incorrect'
            });
        }

        // Reset login attempts on successful login
        await user.resetLoginAttempts();

        // Generate session token
        const sessionToken = user.generateSessionToken();
        await user.save();

        // Generate JWT tokens
        const { accessToken, refreshToken } = generateTokens(user._id);

        // Set secure cookies
        setTokenCookies(res, accessToken, refreshToken);

        // Set session cookie
        res.cookie('sessionToken', sessionToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        });

        // Update last login
        user.lastLogin = Date.now();
        await user.save();

        res.status(200).json({
            success: true,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role,
                verified: user.verified,
                twoFactorEnabled: user.twoFactorEnabled
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({
            error: 'Erreur lors de la connexion'
        });
    }
};

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
exports.logout = async (req, res) => {
    try {
        // Clear cookies
        res.clearCookie('token');
        res.clearCookie('refreshToken');
        res.clearCookie('sessionToken');

        res.status(200).json({
            success: true,
            message: 'Déconnexion réussie'
        });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({
            error: 'Erreur lors de la déconnexion'
        });
    }
};

// @desc    Verify email
// @route   POST /api/auth/verify-email/:token
// @access  Public
exports.verifyEmail = async (req, res) => {
    try {
        const hashedToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            verificationToken: hashedToken,
            verificationExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                error: 'Token invalide ou expiré'
            });
        }

        user.verified = true;
        user.verificationToken = undefined;
        user.verificationExpires = undefined;
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Email vérifié avec succès'
        });
    } catch (err) {
        console.error('Email verification error:', err);
        res.status(500).json({
            error: 'Erreur lors de la vérification de l\'email'
        });
    }
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });

        if (!user) {
            return res.status(404).json({
                error: 'Aucun utilisateur trouvé avec cet email'
            });
        }

        // Generate reset token
        const resetToken = user.generatePasswordResetToken();
        await user.save();

        // Send reset email
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        await sendEmail({
            email: user.email,
            subject: 'Réinitialisation de votre mot de passe',
            template: 'passwordReset',
            context: {
                name: user.firstName,
                url: resetUrl
            }
        });

        res.status(200).json({
            success: true,
            message: 'Email de réinitialisation envoyé'
        });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({
            error: 'Erreur lors de l\'envoi de l\'email de réinitialisation'
        });
    }
};

// @desc    Reset password
// @route   POST /api/auth/reset-password/:token
// @access  Public
exports.resetPassword = async (req, res) => {
    try {
        const hashedToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                error: 'Token invalide ou expiré'
            });
        }

        // Set new password
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Mot de passe réinitialisé avec succès'
        });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({
            error: 'Erreur lors de la réinitialisation du mot de passe'
        });
    }
};

// @desc    Update password
// @route   POST /api/auth/update-password
// @access  Private
exports.updatePassword = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('+password');

        // Verify current password
        const isMatch = await user.matchPassword(req.body.currentPassword);
        if (!isMatch) {
            return res.status(401).json({
                error: 'Mot de passe actuel incorrect'
            });
        }

        // Update password
        user.password = req.body.newPassword;
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Mot de passe mis à jour avec succès'
        });
    } catch (err) {
        console.error('Update password error:', err);
        res.status(500).json({
            error: 'Erreur lors de la mise à jour du mot de passe'
        });
    }
};

// @desc    Refresh token
// @route   POST /api/auth/refresh-token
// @access  Private
exports.refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({
                error: 'Token de rafraîchissement non trouvé'
            });
        }

        // Verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Generate new tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.id);

        // Set new cookies
        setTokenCookies(res, accessToken, newRefreshToken);

        res.status(200).json({
            success: true,
            message: 'Tokens rafraîchis avec succès'
        });
    } catch (err) {
        console.error('Refresh token error:', err);
        res.status(401).json({
            error: 'Token de rafraîchissement invalide'
        });
    }
};

// @desc    Enable 2FA
// @route   POST /api/auth/2fa/enable
// @access  Private
exports.enable2FA = async (req, res) => {
    try {
        const secret = speakeasy.generateSecret({
            name: `Mireb Commercial:${req.user.email}`
        });

        // Generate QR code
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

        // Save secret
        req.user.twoFactorSecret = secret.base32;
        await req.user.save();

        res.status(200).json({
            success: true,
            data: {
                qrCode: qrCodeUrl,
                secret: secret.base32
            }
        });
    } catch (err) {
        console.error('Enable 2FA error:', err);
        res.status(500).json({
            error: 'Erreur lors de l\'activation de la 2FA'
        });
    }
};

// @desc    Verify 2FA
// @route   POST /api/auth/2fa/verify
// @access  Private
exports.verify2FA = async (req, res) => {
    try {
        const { token } = req.body;

        const verified = speakeasy.totp.verify({
            secret: req.user.twoFactorSecret,
            encoding: 'base32',
            token
        });

        if (!verified) {
            return res.status(401).json({
                error: 'Code invalide'
            });
        }

        req.user.twoFactorEnabled = true;
        await req.user.save();

        res.status(200).json({
            success: true,
            message: '2FA activée avec succès'
        });
    } catch (err) {
        console.error('Verify 2FA error:', err);
        res.status(500).json({
            error: 'Erreur lors de la vérification du code 2FA'
        });
    }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getCurrentUser = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        res.status(200).json({
            success: true,
            data: user
        });
    } catch (err) {
        console.error('Get current user error:', err);
        res.status(500).json({
            error: 'Erreur lors de la récupération des données utilisateur'
        });
    }
};

// @desc    Verify device
// @route   POST /api/auth/verify-device
// @access  Private
exports.verifyDevice = async (req, res) => {
    try {
        const { deviceId } = req.body;

        // Add device to trusted devices
        await req.user.addTrustedDevice(deviceId);

        res.status(200).json({
            success: true,
            message: 'Appareil vérifié avec succès'
        });
    } catch (err) {
        console.error('Verify device error:', err);
        res.status(500).json({
            error: 'Erreur lors de la vérification de l\'appareil'
        });
    }
};
