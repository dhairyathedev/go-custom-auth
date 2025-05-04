package main

import (
	//"database/sql"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, Gin!",
		})
	})

	r.POST("/signup", func(c *gin.Context) {
		password := []byte("hello@123")
		hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, gin.H{
				"error": err,
			})
		}
		c.JSON(200, gin.H{
			"message": "Successfully Signed up!!!",
			"hash":    hash,
		})
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
