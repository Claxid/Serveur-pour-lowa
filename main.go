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
	"strings"
	"time"

	_ "modernc.org/sqlite"
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

var db *sql.DB

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "file:./lowa.db")
	if err != nil {
		return err
	}

	// Test connection
	if err = db.Ping(); err != nil {
		return err
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			nom TEXT NOT NULL,
			prenom TEXT NOT NULL,
			sexe TEXT,
			role TEXT DEFAULT 'user',
			date_creation DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Ensure 'role' column exists for older databases
	db.Exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")

	// Create carts table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS carts (
			user_id INTEGER PRIMARY KEY,
			items TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Create purchase_history table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS purchase_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP,
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
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	log.Println("✓ Database initialized successfully (lowa.db)")
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
	err := db.QueryRow("SELECT user_id, expires_at FROM sessions WHERE token = ?", token).Scan(&userID, &expiresAt)
	if err != nil {
		return 0, fmt.Errorf("invalid session")
	}

	if expiresAt.Before(time.Now()) {
		db.Exec("DELETE FROM sessions WHERE token = ?", token)
		return 0, fmt.Errorf("session expired")
	}

	return userID, nil
}

func createSession(userID int) string {
	// Clean expired sessions
	db.Exec("DELETE FROM sessions WHERE expires_at < datetime('now')")

	token := fmt.Sprintf("tok_%d_%d", userID, time.Now().UnixNano())
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days

	db.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
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
	result, err := db.Exec(
		"INSERT INTO users (email, password_hash, nom, prenom, sexe) VALUES (?, ?, ?, ?, ?)",
		req.Email, passwordHash, req.Nom, req.Prenom, req.Sexe,
	)

	if err != nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email already exists"})
		return
	}

	userID, _ := result.LastInsertId()

	// Create empty cart for user
	db.Exec("INSERT INTO carts (user_id, items) VALUES (?, ?)", userID, "[]")

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
		"SELECT id, email, nom, prenom, sexe, date_creation, password_hash FROM users WHERE email = ?",
		req.Email,
	).Scan(&user.ID, &user.Email, &user.Nom, &user.Prenom, &user.Sexe, &user.DateCreation, &storedHash)

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
		"SELECT id, email, nom, prenom, sexe, role, date_creation FROM users WHERE id = ?",
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
		"INSERT OR REPLACE INTO carts (user_id, items, updated_at) VALUES (?, ?, datetime('now'))",
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
	err = db.QueryRow("SELECT items FROM carts WHERE user_id = ?", userID).Scan(&itemsJSON)

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
		"SELECT id, purchase_date, total, items FROM purchase_history WHERE user_id = ? ORDER BY purchase_date DESC",
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
		"INSERT INTO purchase_history (user_id, total, items) VALUES (?, ?, ?)",
		userID, checkoutData.Total, string(itemsJSON),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process purchase"})
		return
	}

	// Clear cart after checkout
	db.Exec("UPDATE carts SET items = '[]', updated_at = datetime('now') WHERE user_id = ?", userID)

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
		db.Exec("DELETE FROM sessions WHERE token = ?", token)
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
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to prepare table"})
		return
	}

	// Upsert preference
	_, err = db.Exec(`INSERT INTO user_preferences (user_id, cookie_consent, updated_at)
		VALUES (?, ?, datetime('now'))
		ON CONFLICT(user_id) DO UPDATE SET cookie_consent = excluded.cookie_consent, updated_at = excluded.updated_at`,
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

	// API Routes
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/user", handleGetUser)
	http.HandleFunc("/api/cart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleGetCart(w, r)
		} else if r.Method == http.MethodPost {
			handleUpdateCart(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/purchase-history", handleGetPurchaseHistory)
	http.HandleFunc("/api/checkout", handleCheckout)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/user-preferences", handleUserPreferences)

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
