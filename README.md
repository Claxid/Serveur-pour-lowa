# LOWA API Server

API backend pour l'application e-commerce LOWA.

## Fonctionnalités

- ✅ Authentification (inscription, connexion, sessions)
- ✅ Gestion de panier
- ✅ Historique d'achats
- ✅ Base de données PostgreSQL

## Endpoints

### Authentification
- `POST /api/register` - Inscription
- `POST /api/login` - Connexion
- `GET /api/user` - Informations utilisateur (nécessite token)
- `POST /api/logout` - Déconnexion

### Panier
- `GET /api/cart` - Récupérer le panier
- `POST /api/cart` - Mettre à jour le panier

### Achats
- `GET /api/purchase-history` - Historique d'achats
- `POST /api/checkout` - Valider un achat

## Déploiement sur Render

1. Créer une base de données PostgreSQL sur Render
2. Créer un Web Service lié à ce repo
3. La variable `DATABASE_URL` sera automatiquement injectée

## Développement local

```bash
# Installer les dépendances
go mod download

# Lancer le serveur (nécessite PostgreSQL local)
export DATABASE_URL="postgres://localhost/lowa?sslmode=disable"
go run main.go
```

Le serveur démarre sur le port 8080 par défaut.
