package routes

import (
	"os"

	"github.com/gin-gonic/gin"
)

// InitializeRoleRoutes sets up all role management routes
func InitializeRoleRoutes(router *gin.Engine, deps *Dependencies) {
	// Get API prefix from environment
	apiPrefix := os.Getenv("API_PREFIX")
	if apiPrefix == "" {
		apiPrefix = "/api/v1"
	}

	// Create API group
	api := router.Group(apiPrefix)

	// Role routes (admin only) - for future implementation
	roles := api.Group("/roles")
	roles.Use(deps.AuthMiddleware.RequireAuth())
	roles.Use(deps.AuthMiddleware.RequireAdmin())
	{
		// Future endpoints:
		// roles.GET("", roleController.GetAllRoles)
		// roles.POST("", roleController.CreateRole)
		// roles.GET("/:id", roleController.GetRoleByID)
		// roles.PUT("/:id", roleController.UpdateRole)
		// roles.DELETE("/:id", roleController.DeleteRole)
	}
}
