const express = require('express');
const { body } = require('express-validator');
const router = express.Router();
const auth = require('../middleware/auth');
const {
    register,
    login,
    logout,
    verifyEmail,
    forgotPassword,
    resetPassword,
    updatePassword,
    refreshToken,
    verifyDevice,
    enable2FA,
    verify2FA,
    getCurrentUser
} = require('../controllers/auth');

// Input validation middleware
const registerValidation = [
    body('firstName')
        .trim()
        .notEmpty()
        .withMessage('Le prénom est requis')
        .isLength({ max: 50 })
        .withMessage('Le prénom ne peut pas dépasser 50 caractères'),
    body('lastName')
        .trim()
        .notEmpty()
        .withMessage('Le nom est requis')
        .isLength({ max: 50 })
        .withMessage('Le nom ne peut pas dépasser 50 caractères'),
    body('email')
        .trim()
        .notEmpty()
        .withMessage('L\'email est requis')
        .isEmail()
        .withMessage('Email invalide')
        .normalizeEmail(),
    body('password')
        .trim()
        .notEmpty()
        .withMessage('Le mot de passe est requis')
        .isLength({ min: 8 })
        .withMessage('Le mot de passe doit contenir au moins 8 caractères')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial')
];

const loginValidation = [
    body('email')
        .trim()
        .notEmpty()
        .withMessage('L\'email est requis')
        .isEmail()
        .withMessage('Email invalide')
        .normalizeEmail(),
    body('password')
        .trim()
        .notEmpty()
        .withMessage('Le mot de passe est requis')
];

const passwordValidation = [
    body('password')
        .trim()
        .notEmpty()
        .withMessage('Le mot de passe est requis')
        .isLength({ min: 8 })
        .withMessage('Le mot de passe doit contenir au moins 8 caractères')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial')
];

// Public routes
router.post('/register', registerValidation, auth.csrfProtection, register);
router.post('/login', loginValidation, auth.loginLimiter, auth.csrfProtection, login);
router.post('/logout', auth.csrfProtection, logout);
router.post('/verify-email/:token', verifyEmail);
router.post('/forgot-password', [
    body('email').isEmail().withMessage('Email invalide')
], forgotPassword);
router.post('/reset-password/:token', passwordValidation, resetPassword);

// Protected routes
router.use(auth.protect); // Apply authentication middleware to all routes below

router.get('/me', getCurrentUser);
router.post('/update-password', passwordValidation, auth.csrfProtection, updatePassword);
router.post('/refresh-token', auth.csrfProtection, refreshToken);

// Device verification routes
router.post('/verify-device', auth.csrfProtection, verifyDevice);

// 2FA routes
router.post('/2fa/enable', auth.csrfProtection, enable2FA);
router.post('/2fa/verify', [
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
], auth.csrfProtection, verify2FA);

// Session management
router.post('/sessions/revoke-all', auth.csrfProtection, async (req, res) => {
    try {
        req.user.sessionToken = undefined;
        req.user.trustedDevices = [];
        await req.user.save();
        
        res.clearCookie('sessionToken');
        res.clearCookie('token');
        
        res.status(200).json({
            success: true,
            message: 'Toutes les sessions ont été révoquées'
        });
    } catch (err) {
        res.status(500).json({
            error: 'Erreur lors de la révocation des sessions'
        });
    }
});

// Security settings
router.get('/security/activity-log', async (req, res) => {
    try {
        const activityLog = req.user.activityLog || [];
        res.status(200).json({
            success: true,
            data: activityLog
        });
    } catch (err) {
        res.status(500).json({
            error: 'Erreur lors de la récupération du journal d\'activité'
        });
    }
});

router.post('/security/trusted-devices/remove', [
    body('deviceId').notEmpty().withMessage('ID de l\'appareil requis')
], auth.csrfProtection, async (req, res) => {
    try {
        await req.user.removeTrustedDevice(req.body.deviceId);
        res.status(200).json({
            success: true,
            message: 'Appareil supprimé des appareils de confiance'
        });
    } catch (err) {
        res.status(500).json({
            error: 'Erreur lors de la suppression de l\'appareil'
        });
    }
});

// Error handling middleware
router.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.status || 500).json({
        error: {
            message: err.message || 'Une erreur est survenue',
            status: err.status || 500
        }
    });
});

module.exports = router;
