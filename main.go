package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string    `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type Session struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	RefreshToken string    `db:"refresh_token"`
	ExpiresAt    time.Time `db:"expires_at"`
	CreatedAt    time.Time `db:"created_at"`
}

var (
	jwtSecret     = []byte(os.Getenv("JWT_SECRET"))
	tokenExpiry   = 15 * time.Minute
	refreshExpiry = 7 * 24 * time.Hour
)

func main() {
	var err error
	db, err := sqlx.Connect("postgres", "user=postgres password=Dts123Dts dbname=go-auth sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, Gin!",
		})
	})

	r.POST("/signup", func(c *gin.Context) {
		signup(c, db)
	})

	r.POST("/login", func(c *gin.Context) {
		login(c, db)
	})

	r.POST("/refresh", func(c *gin.Context) {
		refreshToken(c, db)
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}

func signup(c *gin.Context, db *sqlx.DB) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Check if email is already in use
	var existingUser User
	err := db.Get(&existingUser, "SELECT id FROM users WHERE email = $1", input.Email)
	if err != sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already in use"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error hashing the password",
		})
		return
	}

	userID := uuid.New().String()
	now := time.Now()

	user := User{
		ID:           userID,
		Email:        input.Email,
		PasswordHash: string(hash),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	_, err = db.NamedExec(`INSERT INTO users (id, email, password_hash, created_at, updated_at) 
                          VALUES (:id, :email, :password_hash, :created_at, :updated_at)`, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating the user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully Signed up!!!",
		"user_id": userID,
	})
}

func login(c *gin.Context, db *sqlx.DB) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// fetch user
	var user User
	err := db.Get(&user, "SELECT * FROM users WHERE email=$1", input.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	accessToken, err := generateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	refreshToken, err := generateRefreshToken(user.ID, db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func refreshToken(c *gin.Context, db *sqlx.DB) {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var session Session
	err := db.Get(&session, "SELECT * FROM sessions WHERE refresh_token=$1 AND expires_at > NOW()", input.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	accessToken, err := generateJWT(session.UserID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken})
}

func generateJWT(userID string) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func generateRefreshToken(userID string, db *sqlx.DB) (string, error) {
	refreshToken := uuid.New().String()

	sessionID := uuid.New().String()
	now := time.Now()

	session := Session{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(refreshExpiry),
		CreatedAt:    now,
	}

	_, err := db.NamedExec(`INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at) 
                          VALUES (:id, :user_id, :refresh_token, :expires_at, :created_at)`, session)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}
