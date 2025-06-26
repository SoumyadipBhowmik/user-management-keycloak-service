package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/driver"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/routes"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func connectDatabase() *driver.DB {
	dsn := os.Getenv("DATABASE_URL")
	db, err := driver.ConnectSQL(dsn)
	if err != nil {
		logrus.Fatal("Failed to connect to database:", err)
	}
	return db
}

func startHTTPServer(db *driver.DB) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	origins := strings.Split(allowedOrigins, ",")

	corsConfig := cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	corsMiddleware := cors.New(corsConfig)

	router.Use(corsMiddleware)
	env := os.Getenv("ENV")
	switch env {
	case "PROD":
		logrus.SetLevel(logrus.InfoLevel)
	case "DEV":
		logrus.SetLevel(logrus.DebugLevel)
	default:
		logrus.SetLevel(logrus.WarnLevel)
	}
	logrus.SetFormatter(&logrus.JSONFormatter{})
	routes.InitializeRoutes(router, db)
	port := os.Getenv("PORT")
	if port == "" {
		logrus.Fatal("PORT is not set in .env file")
	}
	log.Println("HTTP Server is running on port", port)
	router.Run(":" + port)
}

func main() {
	db := connectDatabase()
	defer db.Pool.Close()
	startHTTPServer(db)
}
