package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string    `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

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

	// Pass db to the signup handler
	r.POST("/signup", func(c *gin.Context) {
		signup(c, db)
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
		return // Add missing return statement
	}

	// Generate a UUID for the user ID
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
		return // Add missing return statement
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully Signed up!!!",
		"user_id": userID,
	})
}
