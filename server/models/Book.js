const mongoose = require('mongoose');
const crypto = require('crypto');

const bookSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Veuillez fournir le titre du livre'],
        trim: true,
        maxLength: [200, 'Le titre ne peut pas dépasser 200 caractères']
    },
    author: {
        name: {
            type: String,
            required: [true, 'Veuillez fournir le nom de l\'auteur'],
            trim: true
        },
        biography: String,
        photo: String
    },
    description: {
        type: String,
        required: [true, 'Veuillez fournir une description'],
        trim: true
    },
    isbn: {
        type: String,
        unique: true,
        required: [true, 'Veuillez fournir l\'ISBN'],
        match: [
            /^(?:\d{10}|\d{13})$/,
            'Veuillez fournir un ISBN valide (10 ou 13 chiffres)'
        ]
    },
    category: [{
        type: String,
        required: [true, 'Veuillez sélectionner au moins une catégorie'],
        enum: [
            'Romans',
            'Science-Fiction',
            'Policier',
            'Biographies',
            'Histoire',
            'Sciences',
            'Développement personnel',
            'Autres'
        ]
    }],
    language: {
        type: String,
        required: true,
        default: 'fr'
    },
    format: {
        type: String,
        required: true,
        enum: ['PDF', 'EPUB', 'MOBI']
    },
    fileSize: {
        type: Number,
        required: true
    },
    filePath: {
        type: String,
        required: true,
        select: false // Don't return file path in queries
    },
    encryptionKey: {
        type: String,
        required: true,
        select: false // Don't return encryption key in queries
    },
    coverImage: {
        type: String,
        required: true
    },
    price: {
        amount: {
            type: Number,
            required: true,
            min: [0, 'Le prix ne peut pas être négatif']
        },
        currency: {
            type: String,
            required: true,
            default: 'EUR'
        }
    },
    rating: {
        average: {
            type: Number,
            default: 0,
            min: [0, 'La note minimale est 0'],
            max: [5, 'La note maximale est 5']
        },
        count: {
            type: Number,
            default: 0
        }
    },
    reviews: [{
        user: {
            type: mongoose.Schema.ObjectId,
            ref: 'User',
            required: true
        },
        rating: {
            type: Number,
            required: true,
            min: 1,
            max: 5
        },
        comment: {
            type: String,
            required: true,
            trim: true
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    accessLevel: {
        type: String,
        enum: ['free', 'basic', 'premium', 'ultimate'],
        required: true,
        default: 'basic'
    },
    downloadCount: {
        type: Number,
        default: 0
    },
    viewCount: {
        type: Number,
        default: 0
    },
    publishedDate: {
        type: Date,
        required: true
    },
    lastUpdated: Date,
    isActive: {
        type: Boolean,
        default: true
    },
    drm: {
        enabled: {
            type: Boolean,
            default: true
        },
        type: {
            type: String,
            enum: ['watermark', 'encryption', 'none'],
            default: 'encryption'
        }
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Indexes
bookSchema.index({ title: 'text', 'author.name': 'text' });
bookSchema.index({ isbn: 1 });
bookSchema.index({ category: 1 });
bookSchema.index({ accessLevel: 1 });
bookSchema.index({ 'price.amount': 1 });

// Virtual for average rating
bookSchema.virtual('averageRating').get(function() {
    return this.rating.count > 0 ? this.rating.average : 0;
});

// Method to generate secure download URL
bookSchema.methods.generateDownloadUrl = function() {
    const token = crypto.randomBytes(32).toString('hex');
    return {
        url: `/api/books/${this._id}/download/${token}`,
        token,
        expiresIn: '1h'
    };
};

// Method to check if user has access
bookSchema.methods.canAccess = function(userSubscription) {
    const accessLevels = {
        'free': 0,
        'basic': 1,
        'premium': 2,
        'ultimate': 3
    };

    return accessLevels[userSubscription] >= accessLevels[this.accessLevel];
};

// Method to increment download count
bookSchema.methods.incrementDownloads = async function() {
    this.downloadCount += 1;
    await this.save();
};

// Method to increment view count
bookSchema.methods.incrementViews = async function() {
    this.viewCount += 1;
    await this.save();
};

// Method to add review
bookSchema.methods.addReview = async function(userId, rating, comment) {
    this.reviews.push({
        user: userId,
        rating,
        comment
    });

    // Update average rating
    const totalRating = this.reviews.reduce((acc, review) => acc + review.rating, 0);
    this.rating.average = totalRating / this.reviews.length;
    this.rating.count = this.reviews.length;

    await this.save();
};

// Method to remove review
bookSchema.methods.removeReview = async function(reviewId) {
    this.reviews = this.reviews.filter(review => review._id.toString() !== reviewId.toString());

    // Update average rating
    if (this.reviews.length > 0) {
        const totalRating = this.reviews.reduce((acc, review) => acc + review.rating, 0);
        this.rating.average = totalRating / this.reviews.length;
    } else {
        this.rating.average = 0;
    }
    this.rating.count = this.reviews.length;

    await this.save();
};

// Pre-save middleware
bookSchema.pre('save', function(next) {
    this.lastUpdated = Date.now();
    next();
});

// Pre-remove middleware to clean up associated files
bookSchema.pre('remove', async function(next) {
    try {
        // Add file cleanup logic here
        // For example, delete the book file and cover image from storage
        next();
    } catch (err) {
        next(err);
    }
});

const Book = mongoose.model('Book', bookSchema);

module.exports = Book;
