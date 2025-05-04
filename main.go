package main

import (
	//"database/sql"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, Gin!",
		})
	})

	r.POST("/signup", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Successfully Signed up!!!",
		})
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
