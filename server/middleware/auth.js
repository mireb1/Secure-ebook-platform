const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Authentication middleware
exports.protect = async (req, res, next) => {
    try {
        let token;

        // Get token from cookie or authorization header
        if (req.cookies.token) {
            token = req.cookies.token;
        } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({
                error: 'Non autorisé - Authentification requise'
            });
        }

        try {
            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // Check if user still exists
            const user = await User.findById(decoded.id).select('-password');
            if (!user) {
                return res.status(401).json({
                    error: 'Utilisateur non trouvé'
                });
            }

            // Check if user changed password after token was issued
            if (user.passwordChangedAt && decoded.iat < user.passwordChangedAt.getTime() / 1000) {
                return res.status(401).json({
                    error: 'Utilisateur a récemment changé de mot de passe. Veuillez vous reconnecter.'
                });
            }

            // Grant access to protected route
            req.user = user;
            next();
        } catch (err) {
            return res.status(401).json({
                error: 'Token invalide'
            });
        }
    } catch (err) {
        next(err);
    }
};

// Role authorization middleware
exports.authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                error: 'Non autorisé - Rôle insuffisant'
            });
        }
        next();
    };
};

// CSRF Protection middleware
exports.csrfProtection = (req, res, next) => {
    const csrfToken = req.headers['x-csrf-token'];
    if (!csrfToken || csrfToken !== req.cookies.csrfToken) {
        return res.status(403).json({
            error: 'Invalid CSRF token'
        });
    }
    next();
};

// Rate limiting for specific routes
exports.loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts per window
    message: 'Trop de tentatives de connexion. Veuillez réessayer dans 15 minutes.'
});

// Session validation middleware
exports.validateSession = async (req, res, next) => {
    try {
        if (!req.user.sessionToken || req.user.sessionToken !== req.cookies.sessionToken) {
            return res.status(401).json({
                error: 'Session invalide'
            });
        }
        next();
    } catch (err) {
        next(err);
    }
};

// IP filtering middleware
exports.ipFilter = (req, res, next) => {
    const clientIP = req.ip;
    // Add your IP whitelist/blacklist logic here
    // Example: Block specific IPs or allow only certain ranges
    const blacklistedIPs = process.env.BLACKLISTED_IPS ? process.env.BLACKLISTED_IPS.split(',') : [];
    
    if (blacklistedIPs.includes(clientIP)) {
        return res.status(403).json({
            error: 'Accès refusé depuis cette adresse IP'
        });
    }
    next();
};

// Request sanitization middleware
exports.sanitizeRequest = (req, res, next) => {
    // Sanitize request body
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === 'string') {
                req.body[key] = req.body[key].trim().escape();
            }
        });
    }
    next();
};

// Activity logging middleware
exports.logActivity = async (req, res, next) => {
    if (req.user) {
        try {
            await User.findByIdAndUpdate(req.user._id, {
                $push: {
                    activityLog: {
                        action: req.method,
                        path: req.path,
                        timestamp: new Date(),
                        ip: req.ip
                    }
                }
            });
        } catch (err) {
            console.error('Error logging activity:', err);
        }
    }
    next();
};

// Device verification middleware
exports.verifyDevice = async (req, res, next) => {
    const deviceId = req.headers['x-device-id'];
    if (!deviceId) {
        return res.status(401).json({
            error: 'Identifiant de l\'appareil manquant'
        });
    }

    try {
        const user = req.user;
        if (!user.trustedDevices.includes(deviceId)) {
            // Send verification code logic here
            return res.status(401).json({
                error: 'Appareil non reconnu. Vérification requise.',
                requiresVerification: true
            });
        }
        next();
    } catch (err) {
        next(err);
    }
};
