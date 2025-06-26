package routes

import (
	"os"

	"github.com/gin-gonic/gin"
)

// InitializeAuthRoutes sets up all authentication-related routes
func InitializeAuthRoutes(router *gin.Engine, deps *Dependencies) {
	// Get API prefix from environment
	apiPrefix := os.Getenv("API_PREFIX")
	if apiPrefix == "" {
		apiPrefix = "/api/v1"
	}

	// Create API group
	api := router.Group(apiPrefix)

	// Public auth routes (no authentication required)
	authPublic := api.Group("/auth")
	{
		authPublic.POST("/login", deps.AuthController.Login)
		authPublic.POST("/register", deps.AuthController.Register)
	}

	// Protected auth routes (authentication required)
	authProtected := api.Group("/auth")
	authProtected.Use(deps.AuthMiddleware.RequireAuth())
	{
		authProtected.GET("/me", deps.AuthController.GetMe)
		authProtected.GET("/validate", deps.AuthController.ValidateToken)
	}
}
