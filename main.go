package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
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
	jwtSecret     = []byte("a1ea4e24f988988483046a75df5f1f5e973aa0889cbfe2dc7c64613cf32f1ae1158bd8cedd4f3a9074827a9779860bc6a197917e1c5c874ff869cdb32344658679b25f469e7e5f9a5d09964a58cae6659c1a38180af3ca833533a0a5521f7d3d63341c9ef9df4c25b40329dc6cabe0f214b56daa060246e4516a63aacdde1d1525e47c138be284f9243770b0eb5f0af9be01327443d62ab819a0f4998a20e7b9ab8960218a651dc8e107207338ae1f2bf957c18519d70733b84590edef230526af02faa72f29dd58ff2c822f34c6734119232c836ebafbb028797b8a4368b0125f5e67fb0dee67d6619a982f499957c2a3e83bdebd5961e8f06026624d08e076")
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

	c.JSON(200, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})

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
