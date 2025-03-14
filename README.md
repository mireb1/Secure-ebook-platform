# Mireb Commercial - Plateforme E-book Sécurisée

Une plateforme sécurisée pour la distribution et la gestion d'e-books avec authentification avancée, protection DRM et gestion des abonnements.

## Fonctionnalités de Sécurité

- Authentification sécurisée à deux facteurs (2FA)
- Protection CSRF
- Limitation de débit (Rate limiting)
- Gestion sécurisée des sessions
- Vérification des appareils
- Cryptage des e-books
- Journalisation des activités
- Protection DRM
- Gestion sécurisée des mots de passe
- Vérification par email

## Architecture

### Frontend
- Interface utilisateur responsive avec Tailwind CSS
- Pages sécurisées pour l'authentification et la navigation
- Gestion des tokens et sessions côté client
- Intégration avec l'API REST sécurisée

### Backend
- API REST sécurisée avec Express.js
- Base de données MongoDB avec schémas validés
- Système d'authentification avancé
- Gestion des fichiers cryptés
- Système de journalisation

## Configuration Requise

- Node.js (v14+)
- MongoDB (v4+)
- Serveur SMTP pour les emails

## Installation

1. Cloner le dépôt :
```bash
git clone https://github.com/votre-repo/secure-ebook-platform.git
cd secure-ebook-platform
```

2. Installer les dépendances :
```bash
# Installation des dépendances du serveur
cd server
npm install

# Installation des dépendances du client (si nécessaire)
cd ../client
npm install
```

3. Configurer les variables d'environnement :
```bash
# Dans le dossier server
cp .env.example .env
```
Modifier le fichier `.env` avec vos configurations.

4. Démarrer le serveur :
```bash
# Dans le dossier server
npm run dev
```

## Structure du Projet

```
secure-ebook-platform/
├── server/
│   ├── controllers/     # Logique métier
│   ├── middleware/      # Middleware de sécurité
│   ├── models/         # Modèles de données
│   ├── routes/         # Routes API
│   ├── utils/          # Utilitaires
│   └── server.js       # Point d'entrée
├── public/             # Fichiers statiques
└── README.md
```

## Sécurité

### Authentification
- Sessions sécurisées avec JWT
- Protection contre la force brute
- Verrouillage de compte après tentatives échouées
- Vérification d'email obligatoire
- Support 2FA

### Protection des Données
- Cryptage AES-256-GCM pour les e-books
- Watermarking digital
- Gestion des droits d'accès
- Validation des entrées
- Protection XSS et CSRF

### Surveillance
- Journalisation des activités
- Détection des appareils suspects
- Alertes de sécurité par email

## API Endpoints

### Authentification
- `POST /api/auth/register` - Inscription
- `POST /api/auth/login` - Connexion
- `POST /api/auth/logout` - Déconnexion
- `POST /api/auth/verify-email` - Vérification email
- `POST /api/auth/forgot-password` - Mot de passe oublié
- `POST /api/auth/reset-password` - Réinitialisation mot de passe
- `POST /api/auth/2fa/enable` - Activation 2FA
- `POST /api/auth/2fa/verify` - Vérification 2FA

### E-books
- `GET /api/books` - Liste des e-books
- `GET /api/books/:id` - Détails d'un e-book
- `POST /api/books/:id/purchase` - Achat d'un e-book
- `GET /api/books/:id/download` - Téléchargement sécurisé
- `POST /api/books/:id/reviews` - Ajouter un avis

## Niveaux d'Abonnement

### Basique (9.99€/mois)
- Accès à la bibliothèque de base
- 5 téléchargements par mois
- Lecture sur un appareil

### Premium (19.99€/mois)
- Accès à la bibliothèque premium
- 15 téléchargements par mois
- Lecture sur 3 appareils
- Mode hors ligne
- Livres audio inclus

### Ultimate (29.99€/mois)
- Accès illimité
- Téléchargements illimités
- Lecture sur 5 appareils
- Contenu exclusif
- Support prioritaire

## Sécurité des E-books

### DRM
- Cryptage AES-256-GCM
- Watermarking personnalisé
- Contrôle des accès
- Limitation des appareils

### Téléchargements
- Liens de téléchargement temporaires
- Vérification de session
- Limitation par abonnement
- Journalisation des accès

## Contribution

1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## Licence

Propriétaire - Tous droits réservés

## Support

Pour toute question de sécurité, contactez security@mireb-commercial.com
