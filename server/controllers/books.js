const Book = require('../models/Book');
const User = require('../models/User');
const crypto = require('crypto');
const { validationResult } = require('express-validator');

// Helper function to encrypt file content
const encryptContent = (content, key) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(content);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
        iv: iv.toString('hex'),
        encryptedContent: encrypted.toString('hex'),
        authTag: authTag.toString('hex')
    };
};

// Helper function to decrypt file content
const decryptContent = (encrypted, key, iv, authTag) => {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(key, 'hex'),
        Buffer.from(iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(Buffer.from(encrypted, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
};

// @desc    Get all books with pagination and filters
// @route   GET /api/books
// @access  Private
exports.getBooks = async (req, res) => {
    try {
        const page = parseInt(req.query.page, 10) || 1;
        const limit = parseInt(req.query.limit, 10) || 10;
        const startIndex = (page - 1) * limit;

        // Build query
        const query = {};
        
        // Filter by category
        if (req.query.category) {
            query.category = req.query.category;
        }

        // Filter by access level based on user subscription
        const accessLevels = {
            'free': ['free'],
            'basic': ['free', 'basic'],
            'premium': ['free', 'basic', 'premium'],
            'ultimate': ['free', 'basic', 'premium', 'ultimate']
        };
        query.accessLevel = { $in: accessLevels[req.user.subscription.type] };

        // Execute query
        const books = await Book.find(query)
            .select('-filePath -encryptionKey')
            .skip(startIndex)
            .limit(limit)
            .sort({ publishedDate: -1 });

        // Get total count
        const total = await Book.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                books,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (err) {
        console.error('Get books error:', err);
        res.status(500).json({
            error: 'Erreur lors de la récupération des livres'
        });
    }
};

// @desc    Get single book
// @route   GET /api/books/:id
// @access  Private
exports.getBook = async (req, res) => {
    try {
        const book = await Book.findById(req.params.id)
            .select('-filePath -encryptionKey')
            .populate('reviews.user', 'firstName lastName');

        if (!book) {
            return res.status(404).json({
                error: 'Livre non trouvé'
            });
        }

        // Check access level
        if (!book.canAccess(req.user.subscription.type)) {
            return res.status(403).json({
                error: 'Accès non autorisé à ce livre'
            });
        }

        // Increment view count
        await book.incrementViews();

        res.status(200).json({
            success: true,
            data: book
        });
    } catch (err) {
        console.error('Get book error:', err);
        res.status(500).json({
            error: 'Erreur lors de la récupération du livre'
        });
    }
};

// @desc    Purchase book
// @route   POST /api/books/:id/purchase
// @access  Private
exports.purchaseBook = async (req, res) => {
    try {
        const book = await Book.findById(req.params.id);

        if (!book) {
            return res.status(404).json({
                error: 'Livre non trouvé'
            });
        }

        // Check if user already owns the book
        const user = await User.findById(req.user.id);
        const alreadyPurchased = user.library.some(item => 
            item.book.toString() === book._id.toString()
        );

        if (alreadyPurchased) {
            return res.status(400).json({
                error: 'Vous possédez déjà ce livre'
            });
        }

        // Add book to user's library
        user.library.push({
            book: book._id,
            purchaseDate: Date.now(),
            progress: 0
        });

        await user.save();

        res.status(200).json({
            success: true,
            message: 'Livre acheté avec succès'
        });
    } catch (err) {
        console.error('Purchase book error:', err);
        res.status(500).json({
            error: 'Erreur lors de l\'achat du livre'
        });
    }
};

// @desc    Download book
// @route   GET /api/books/:id/download/:token
// @access  Private
exports.downloadBook = async (req, res) => {
    try {
        const book = await Book.findById(req.params.id)
            .select('+filePath +encryptionKey');

        if (!book) {
            return res.status(404).json({
                error: 'Livre non trouvé'
            });
        }

        // Verify download token
        const user = await User.findById(req.user.id);
        const userBook = user.library.find(item => 
            item.book.toString() === book._id.toString()
        );

        if (!userBook) {
            return res.status(403).json({
                error: 'Vous devez acheter ce livre pour le télécharger'
            });
        }

        // Check download limits based on subscription
        const downloadLimits = {
            'basic': 5,
            'premium': 15,
            'ultimate': Infinity
        };

        const monthlyDownloads = user.library.filter(item => {
            const downloadDate = new Date(item.lastAccessed);
            const oneMonthAgo = new Date();
            oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
            return downloadDate > oneMonthAgo;
        }).length;

        if (monthlyDownloads >= downloadLimits[user.subscription.type]) {
            return res.status(403).json({
                error: 'Limite de téléchargements mensuelle atteinte'
            });
        }

        // Update last accessed
        userBook.lastAccessed = Date.now();
        await user.save();

        // Increment download count
        await book.incrementDownloads();

        // Add watermark if enabled
        let content = await fs.promises.readFile(book.filePath);
        if (book.drm.enabled && book.drm.type === 'watermark') {
            const watermark = `Ce livre appartient à ${user.firstName} ${user.lastName}`;
            // Add watermark logic here based on file format
        }

        // Encrypt content for secure delivery
        const { iv, encryptedContent, authTag } = encryptContent(content, book.encryptionKey);

        res.status(200).json({
            success: true,
            data: {
                content: encryptedContent,
                iv,
                authTag,
                format: book.format
            }
        });
    } catch (err) {
        console.error('Download book error:', err);
        res.status(500).json({
            error: 'Erreur lors du téléchargement du livre'
        });
    }
};

// @desc    Add book review
// @route   POST /api/books/:id/reviews
// @access  Private
exports.addReview = async (req, res) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const book = await Book.findById(req.params.id);

        if (!book) {
            return res.status(404).json({
                error: 'Livre non trouvé'
            });
        }

        // Check if user has purchased the book
        const user = await User.findById(req.user.id);
        const hasPurchased = user.library.some(item => 
            item.book.toString() === book._id.toString()
        );

        if (!hasPurchased) {
            return res.status(403).json({
                error: 'Vous devez acheter le livre pour poster un avis'
            });
        }

        // Check if user has already reviewed
        const hasReviewed = book.reviews.some(review => 
            review.user.toString() === req.user.id
        );

        if (hasReviewed) {
            return res.status(400).json({
                error: 'Vous avez déjà posté un avis pour ce livre'
            });
        }

        // Add review
        await book.addReview(req.user.id, req.body.rating, req.body.comment);

        res.status(201).json({
            success: true,
            message: 'Avis ajouté avec succès'
        });
    } catch (err) {
        console.error('Add review error:', err);
        res.status(500).json({
            error: 'Erreur lors de l\'ajout de l\'avis'
        });
    }
};

// @desc    Update reading progress
// @route   POST /api/books/:id/progress
// @access  Private
exports.updateProgress = async (req, res) => {
    try {
        const { progress } = req.body;

        // Validate progress
        if (progress < 0 || progress > 100) {
            return res.status(400).json({
                error: 'Le progrès doit être entre 0 et 100'
            });
        }

        // Find user's book in library
        const user = await User.findById(req.user.id);
        const userBook = user.library.find(item => 
            item.book.toString() === req.params.id
        );

        if (!userBook) {
            return res.status(404).json({
                error: 'Livre non trouvé dans votre bibliothèque'
            });
        }

        // Update progress
        userBook.progress = progress;
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Progrès mis à jour avec succès'
        });
    } catch (err) {
        console.error('Update progress error:', err);
        res.status(500).json({
            error: 'Erreur lors de la mise à jour du progrès'
        });
    }
};

// @desc    Save bookmarks
// @route   POST /api/books/:id/bookmarks
// @access  Private
exports.saveBookmarks = async (req, res) => {
    try {
        const { bookmarks } = req.body;

        // Validate bookmarks array
        if (!Array.isArray(bookmarks)) {
            return res.status(400).json({
                error: 'Format de marque-pages invalide'
            });
        }

        // Find user's book in library
        const user = await User.findById(req.user.id);
        const userBook = user.library.find(item => 
            item.book.toString() === req.params.id
        );

        if (!userBook) {
            return res.status(404).json({
                error: 'Livre non trouvé dans votre bibliothèque'
            });
        }

        // Update bookmarks
        userBook.bookmarks = bookmarks;
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Marque-pages sauvegardés avec succès'
        });
    } catch (err) {
        console.error('Save bookmarks error:', err);
        res.status(500).json({
            error: 'Erreur lors de la sauvegarde des marque-pages'
        });
    }
};

// @desc    Get bookmarks
// @route   GET /api/books/:id/bookmarks
// @access  Private
exports.getBookmarks = async (req, res) => {
    try {
        // Find user's book in library
        const user = await User.findById(req.user.id);
        const userBook = user.library.find(item => 
            item.book.toString() === req.params.id
        );

        if (!userBook) {
            return res.status(404).json({
                error: 'Livre non trouvé dans votre bibliothèque'
            });
        }

        res.status(200).json({
            success: true,
            bookmarks: userBook.bookmarks || []
        });
    } catch (err) {
        console.error('Get bookmarks error:', err);
        res.status(500).json({
            error: 'Erreur lors de la récupération des marque-pages'
        });
    }
};

// @desc    Get book reviews
// @route   GET /api/books/:id/reviews
// @access  Private
exports.getBookReviews = async (req, res) => {
    try {
        const book = await Book.findById(req.params.id)
            .select('reviews')
            .populate('reviews.user', 'firstName lastName');

        if (!book) {
            return res.status(404).json({
                error: 'Livre non trouvé'
            });
        }

        res.status(200).json({
            success: true,
            data: book.reviews
        });
    } catch (err) {
        console.error('Get reviews error:', err);
        res.status(500).json({
            error: 'Erreur lors de la récupération des avis'
        });
    }
};

// @desc    Search books
// @route   GET /api/books/search
// @access  Private
exports.searchBooks = async (req, res) => {
    try {
        const { q, category, format, language } = req.query;
        
        // Build search query
        const searchQuery = {};
        
        if (q) {
            searchQuery.$text = { $search: q };
        }
        
        if (category) {
            searchQuery.category = category;
        }
        
        if (format) {
            searchQuery.format = format;
        }
        
        if (language) {
            searchQuery.language = language;
        }

        // Filter by access level
        const accessLevels = {
            'free': ['free'],
            'basic': ['free', 'basic'],
            'premium': ['free', 'basic', 'premium'],
            'ultimate': ['free', 'basic', 'premium', 'ultimate']
        };
        searchQuery.accessLevel = { $in: accessLevels[req.user.subscription.type] };

        // Execute search
        const books = await Book.find(searchQuery)
            .select('-filePath -encryptionKey')
            .sort({ score: { $meta: 'textScore' } });

        res.status(200).json({
            success: true,
            data: books
        });
    } catch (err) {
        console.error('Search books error:', err);
        res.status(500).json({
            error: 'Erreur lors de la recherche de livres'
        });
    }
};
