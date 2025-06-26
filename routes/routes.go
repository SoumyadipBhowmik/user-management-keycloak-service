package routes

import (
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/controllers"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/driver"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/middleware"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/repository"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/service"
	"github.com/gin-gonic/gin"
)

// Dependencies holds all the dependencies needed for routes
type Dependencies struct {
	AuthController *controllers.AuthController
	UserController *controllers.UserController
	AuthMiddleware *middleware.AuthMiddleware
}

func InitializeRoutes(router *gin.Engine, db *driver.DB) {
	// Initialize dependencies
	deps := initializeDependencies(db)

	// Initialize route groups
	InitializeAuthRoutes(router, deps)
	InitializeUserRoutes(router, deps)
}

// initializeDependencies creates all the services, repositories, and controllers
func initializeDependencies(db *driver.DB) *Dependencies {
	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	// Initialize Keycloak client
	keycloakClient := service.NewKeycloakClient()

	// Initialize services
	authService := service.NewAuthService(userRepo, roleRepo, keycloakClient)
	userService := service.NewUserService(userRepo, roleRepo, keycloakClient)

	// Initialize controllers
	authController := controllers.NewAuthController(authService)
	userController := controllers.NewUserController(userService)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(userService)

	return &Dependencies{
		AuthController: authController,
		UserController: userController,
		AuthMiddleware: authMiddleware,
	}
}
