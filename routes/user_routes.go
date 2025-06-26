package routes

import (
	"os"

	"github.com/gin-gonic/gin"
)

// InitializeUserRoutes sets up all user management routes
func InitializeUserRoutes(router *gin.Engine, deps *Dependencies) {
	// Get API prefix from environment
	apiPrefix := os.Getenv("API_PREFIX")
	if apiPrefix == "" {
		apiPrefix = "/api/v1"
	}

	// Create API group
	api := router.Group(apiPrefix)

	// User routes (admin only)
	users := api.Group("/users")
	users.Use(deps.AuthMiddleware.RequireAuth())
	users.Use(deps.AuthMiddleware.RequireAdmin())
	{
		users.GET("", deps.UserController.GetAllUsers)
		users.GET("/:id", deps.UserController.GetUserByID)
		users.PUT("/:id/roles", deps.UserController.UpdateUserRoles)
	}
}
