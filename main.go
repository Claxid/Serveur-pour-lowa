package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	pq "github.com/lib/pq"
)

type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	Nom          string    `json:"nom"`
	Prenom       string    `json:"prenom"`
	Sexe         string    `json:"sexe"`
	Role         string    `json:"role"`
	DateCreation time.Time `json:"date_creation"`
}

type CartItem struct {
	ProductID int `json:"product_id"`
	Quantity  int `json:"quantity"`
}

type PurchaseHistory struct {
	ID    int        `json:"id"`
	Date  time.Time  `json:"date"`
	Total float64    `json:"total"`
	Items []CartItem `json:"items"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Nom      string `json:"nom"`
	Prenom   string `json:"prenom"`
	Sexe     string `json:"sexe"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Product struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Price       float64   `json:"price"`
	Description string    `json:"description"`
	Image       string    `json:"image"`
	Category    string    `json:"category"`
	Subcategory string    `json:"subcategory"`
	Collection  string    `json:"collection"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var db *sql.DB

func initDB() error {
	var err error
	// Use DATABASE_URL from environment, fallback to local postgres
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Println("DATABASE_URL not set, using local postgres://localhost/lowa?sslmode=disable")
		databaseURL = "postgres://localhost/lowa?sslmode=disable"
	}

	db, err = sql.Open("postgres", databaseURL)
	if err != nil {
		return err
	}

	// Test connection with retries (helps on cold start)
	for i := 1; i <= 10; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		log.Printf("DB ping failed (attempt %d/10): %v", i, err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			nom TEXT NOT NULL,
			prenom TEXT NOT NULL,
			sexe TEXT,
			role TEXT DEFAULT 'user',
			cookie_consent TEXT,
			date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Ensure columns exist for older databases
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'")
	db.Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS cookie_consent TEXT")

	// Create carts table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS carts (
			user_id INTEGER PRIMARY KEY,
			items TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Create purchase_history table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS purchase_history (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			total REAL NOT NULL,
			items TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Create sessions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Create products table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS products (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			price REAL NOT NULL,
			description TEXT,
			image TEXT,
			category TEXT,
			subcategory TEXT,
			collection TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	log.Println("✓ Database initialized successfully (PostgreSQL)")
	return nil
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func getSessionUserID(r *http.Request) (int, error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return 0, fmt.Errorf("no session")
	}

	var userID int
	var expiresAt time.Time
	err := db.QueryRow("SELECT user_id, expires_at FROM sessions WHERE token = $1", token).Scan(&userID, &expiresAt)
	if err != nil {
		return 0, fmt.Errorf("invalid session")
	}

	if expiresAt.Before(time.Now()) {
		db.Exec("DELETE FROM sessions WHERE token = $1", token)
		return 0, fmt.Errorf("session expired")
	}

	return userID, nil
}

func createSession(userID int) string {
	// Clean expired sessions
	db.Exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")

	token := fmt.Sprintf("tok_%d_%d", userID, time.Now().UnixNano())
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days

	db.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)",
		token, userID, expiresAt)

	return token
}

// API Endpoints
func handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	if req.Email == "" || req.Password == "" || req.Nom == "" || req.Prenom == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing required fields"})
		return
	}

	passwordHash := hashPassword(req.Password)
	var userID int64
	err := db.QueryRow(
		"INSERT INTO users (email, password_hash, nom, prenom, sexe) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		req.Email, passwordHash, req.Nom, req.Prenom, req.Sexe,
	).Scan(&userID)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "Email already exists"})
			return
		}

		log.Printf("registration insert failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Registration failed"})
		return
	}

	// Create empty cart for user
	db.Exec("INSERT INTO carts (user_id, items) VALUES ($1, $2)", userID, "[]")

	token := createSession(int(userID))

	log.Printf("New user registered: %s (ID: %d)", req.Email, userID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user_id": userID,
		"token":   token,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	passwordHash := hashPassword(req.Password)
	var user User
	var storedHash string

	err := db.QueryRow(
		"SELECT id, email, nom, prenom, sexe, role, date_creation, password_hash FROM users WHERE email = $1",
		req.Email,
	).Scan(&user.ID, &user.Email, &user.Nom, &user.Prenom, &user.Sexe, &user.Role, &user.DateCreation, &storedHash)

	if err != nil || storedHash != passwordHash {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	token := createSession(user.ID)
	log.Printf("User logged in: %s (ID: %d)", user.Email, user.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   token,
	})
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getSessionUserID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
		return
	}

	var user User
	err = db.QueryRow(
		"SELECT id, email, nom, prenom, sexe, role, date_creation FROM users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Email, &user.Nom, &user.Prenom, &user.Sexe, &user.Role, &user.DateCreation)

	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "User not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func handleUpdateCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getSessionUserID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
		return
	}

	var items []CartItem
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	itemsJSON, _ := json.Marshal(items)
	_, err = db.Exec(
		"INSERT INTO carts (user_id, items, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP) ON CONFLICT (user_id) DO UPDATE SET items = $2, updated_at = CURRENT_TIMESTAMP",
		userID, string(itemsJSON),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update cart"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

func handleGetCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getSessionUserID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
		return
	}

	var itemsJSON string
	err = db.QueryRow("SELECT items FROM carts WHERE user_id = $1", userID).Scan(&itemsJSON)

	if err != nil {
		// No cart yet, return empty array
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]CartItem{})
		return
	}

	var items []CartItem
	json.Unmarshal([]byte(itemsJSON), &items)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(items)
}

func handleGetPurchaseHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getSessionUserID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
		return
	}

	rows, err := db.Query(
		"SELECT id, purchase_date, total, items FROM purchase_history WHERE user_id = $1 ORDER BY purchase_date DESC",
		userID,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch history"})
		return
	}
	defer rows.Close()

	var history []PurchaseHistory
	for rows.Next() {
		var p PurchaseHistory
		var itemsJSON string
		rows.Scan(&p.ID, &p.Date, &p.Total, &itemsJSON)
		json.Unmarshal([]byte(itemsJSON), &p.Items)
		history = append(history, p)
	}

	if history == nil {
		history = []PurchaseHistory{}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(history)
}

func handleCheckout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, err := getSessionUserID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
		return
	}

	var checkoutData struct {
		Items []CartItem `json:"items"`
		Total float64    `json:"total"`
	}

	if err := json.NewDecoder(r.Body).Decode(&checkoutData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	itemsJSON, _ := json.Marshal(checkoutData.Items)
	_, err = db.Exec(
		"INSERT INTO purchase_history (user_id, total, items) VALUES ($1, $2, $3)",
		userID, checkoutData.Total, string(itemsJSON),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process purchase"})
		return
	}

	// Clear cart after checkout
	db.Exec("UPDATE carts SET items = '[]', updated_at = CURRENT_TIMESTAMP WHERE user_id = $1", userID)

	log.Printf("Purchase completed for user ID: %d (Total: %.2f EUR)", userID, checkoutData.Total)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Purchase completed",
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token := r.Header.Get("Authorization")

	if token != "" {
		db.Exec("DELETE FROM sessions WHERE token = $1", token)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

// Save user preferences (e.g., cookie consent)
func handleUserPreferences(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	userID, err := getSessionUserID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not authenticated"})
		return
	}

	var body struct {
		CookieConsent string `json:"cookie_consent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CookieConsent == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Create table for preferences if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_preferences (
		user_id INTEGER PRIMARY KEY,
		cookie_consent TEXT,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to prepare table"})
		return
	}

	// Upsert preference
	_, err = db.Exec(`INSERT INTO user_preferences (user_id, cookie_consent, updated_at)
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET cookie_consent = excluded.cookie_consent, updated_at = CURRENT_TIMESTAMP`,
		userID, body.CookieConsent,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save preferences"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

// CORS Middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from your Vercel frontend
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Helper: check admin role
func isAdmin(r *http.Request) (int, bool) {
	userID, err := getSessionUserID(r)
	if err != nil {
		return 0, false
	}

	var role string
	if err := db.QueryRow("SELECT role FROM users WHERE id = $1", userID).Scan(&role); err != nil || role != "admin" {
		return userID, false
	}
	return userID, true
}

// Get all products
func handleGetProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
		SELECT id, name, price, description, image, category, subcategory, collection, created_at, updated_at
		FROM products
		ORDER BY created_at DESC`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch products"})
		return
	}
	defer rows.Close()

	products := []Product{}
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.Description, &p.Image, &p.Category, &p.Subcategory, &p.Collection, &p.CreatedAt, &p.UpdatedAt); err == nil {
			products = append(products, p)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(products)
}

// Create product (admin only)
func handleCreateProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_, admin := isAdmin(r)
	if !admin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	var product Product
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	err := db.QueryRow(`
		INSERT INTO products (name, price, description, image, category, subcategory, collection)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		product.Name, product.Price, product.Description, product.Image, product.Category, product.Subcategory, product.Collection,
	).Scan(&product.ID, &product.CreatedAt, &product.UpdatedAt)
	if err != nil {
		log.Printf("Error creating product: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create product"})
		return
	}

	log.Printf("Product created: %s (ID: %d)", product.Name, product.ID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(product)
}

// Update product (admin only)
func handleUpdateProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_, admin := isAdmin(r)
	if !admin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	var product Product
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	if product.ID == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Product ID required"})
		return
	}

	err := db.QueryRow(`
		UPDATE products
		SET name = $1, price = $2, description = $3, image = $4, category = $5, subcategory = $6, collection = $7, updated_at = CURRENT_TIMESTAMP
		WHERE id = $8
		RETURNING updated_at`,
		product.Name, product.Price, product.Description, product.Image, product.Category, product.Subcategory, product.Collection, product.ID,
	).Scan(&product.UpdatedAt)
	if err != nil {
		log.Printf("Error updating product: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update product"})
		return
	}

	log.Printf("Product updated: %s (ID: %d)", product.Name, product.ID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(product)
}

// Delete product (admin only)
func handleDeleteProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_, admin := isAdmin(r)
	if !admin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
		return
	}

	productIDStr := r.URL.Query().Get("id")
	if productIDStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Product ID required"})
		return
	}

	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid product ID"})
		return
	}

	result, err := db.Exec("DELETE FROM products WHERE id = $1", productID)
	if err != nil {
		log.Printf("Error deleting product: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete product"})
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Product not found"})
		return
	}

	log.Printf("Product deleted: ID %d", productID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"success": "Product deleted"})
}

func main() {
	dir := flag.String("dir", ".", "directory to serve")
	addr := flag.String("addr", ":8080", "address to listen on")
	flag.Parse()

	// If PORT env is set (Render/Fly/etc.), override addr
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if strings.HasPrefix(portEnv, ":") {
			*addr = portEnv
		} else {
			*addr = ":" + portEnv
		}
	}

	// Initialize database
	if err := initDB(); err != nil {
		log.Fatal("❌ Database initialization failed:", err)
	}
	defer db.Close()

	// API Routes with CORS
	http.HandleFunc("/api/register", corsMiddleware(handleRegister))
	http.HandleFunc("/api/login", corsMiddleware(handleLogin))
	http.HandleFunc("/api/user", corsMiddleware(handleGetUser))
	http.HandleFunc("/api/cart", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleGetCart(w, r)
		} else if r.Method == http.MethodPost {
			handleUpdateCart(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	http.HandleFunc("/api/purchase-history", corsMiddleware(handleGetPurchaseHistory))
	http.HandleFunc("/api/checkout", corsMiddleware(handleCheckout))
	http.HandleFunc("/api/logout", corsMiddleware(handleLogout))
	http.HandleFunc("/api/user-preferences", corsMiddleware(handleUserPreferences))

	// Products API routes
	http.HandleFunc("/api/products", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetProducts(w, r)
		case http.MethodPost:
			handleCreateProduct(w, r)
		case http.MethodPut:
			handleUpdateProduct(w, r)
		case http.MethodDelete:
			handleDeleteProduct(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	// Static files
	fs := http.FileServer(http.Dir(*dir))
	http.Handle("/", fs)

	log.Printf("🌿 Serving %s on HTTP %s\n", *dir, *addr)

	// Build a localhost URL for convenience
	port := strings.TrimLeft(*addr, ":")
	if port == "" {
		port = "80"
	}
	url := fmt.Sprintf("http://localhost:%s/", port)

	fmt.Printf("\x1b]8;;%s\x07%s\x1b]8;;\x07\n", url, url)
	fmt.Println(url)

	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}
