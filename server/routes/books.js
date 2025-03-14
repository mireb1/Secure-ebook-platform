const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const auth = require('../middleware/auth');
const {
    getBooks,
    getBook,
    purchaseBook,
    downloadBook,
    addReview,
    getBookReviews,
    searchBooks
} = require('../controllers/books');

// Apply protection middleware to all routes
router.use(auth.protect);

// Input validation middleware
const reviewValidation = [
    body('rating')
        .isInt({ min: 1, max: 5 })
        .withMessage('La note doit être comprise entre 1 et 5'),
    body('comment')
        .trim()
        .notEmpty()
        .withMessage('Le commentaire est requis')
        .isLength({ max: 500 })
        .withMessage('Le commentaire ne peut pas dépasser 500 caractères')
];

// Public routes (still protected by auth but no special permissions needed)
router.get('/', getBooks);
router.get('/search', searchBooks);
router.get('/:id', getBook);
router.get('/:id/reviews', getBookReviews);

// Routes requiring valid subscription
router.post('/:id/purchase', auth.validateSession, purchaseBook);
router.get('/:id/download/:token', auth.validateSession, downloadBook);

// Review routes
router.post('/:id/reviews', reviewValidation, auth.validateSession, addReview);

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
