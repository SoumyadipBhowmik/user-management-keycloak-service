package middleware

import (
	"net/http"
	"strings"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/dto"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthMiddleware struct {
	userService *service.UserService
}

func NewAuthMiddleware(userService *service.UserService) *AuthMiddleware {
	return &AuthMiddleware{
		userService: userService,
	}
}

// RequireAuth validates bearer token and sets user in context
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "Authorization header required",
				Code:    "MISSING_AUTH_HEADER",
			})
			c.Abort()
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "Invalid authorization header format",
				Code:    "INVALID_AUTH_FORMAT",
			})
			c.Abort()
			return
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "Bearer token required",
				Code:    "MISSING_TOKEN",
			})
			c.Abort()
			return
		}

		// Validate token and get user
		user, err := m.userService.GetCurrentUserFromToken(c.Request.Context(), token)
		if err != nil {
			logrus.WithError(err).Error("Token validation failed")
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "Invalid or expired token",
				Code:    "INVALID_TOKEN",
			})
			c.Abort()
			return
		}

		// Set user in context
		c.Set("user", user)
		c.Set("user_id", user.ID)
		c.Set("access_token", token)

		c.Next()
	}
}

// RequireAdmin validates that user has admin role
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context (set by RequireAuth)
		userInterface, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "User not found in context",
				Code:    "USER_NOT_FOUND",
			})
			c.Abort()
			return
		}

		user, ok := userInterface.(*dto.UserResponse)
		if !ok {
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
				Message: "Invalid user context",
				Code:    "INVALID_USER_CONTEXT",
			})
			c.Abort()
			return
		}

		// Check if user has admin role
		isAdmin := false
		for _, role := range user.Roles {
			if role.Name == "admin" { // Could make this configurable
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			c.JSON(http.StatusForbidden, dto.ErrorResponse{
				Message: "Admin role required",
				Code:    "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole validates that user has specific role
func (m *AuthMiddleware) RequireRole(roleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context (set by RequireAuth)
		userInterface, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "User not found in context",
				Code:    "USER_NOT_FOUND",
			})
			c.Abort()
			return
		}

		user, ok := userInterface.(*dto.UserResponse)
		if !ok {
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
				Message: "Invalid user context",
				Code:    "INVALID_USER_CONTEXT",
			})
			c.Abort()
			return
		}

		// Check if user has the required role
		hasRole := false
		for _, role := range user.Roles {
			if role.Name == roleName {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, dto.ErrorResponse{
				Message: "Required role: " + roleName,
				Code:    "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole validates that user has at least one of the specified roles
func (m *AuthMiddleware) RequireAnyRole(roleNames ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context (set by RequireAuth)
		userInterface, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Message: "User not found in context",
				Code:    "USER_NOT_FOUND",
			})
			c.Abort()
			return
		}

		user, ok := userInterface.(*dto.UserResponse)
		if !ok {
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
				Message: "Invalid user context",
				Code:    "INVALID_USER_CONTEXT",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, userRole := range user.Roles {
			for _, requiredRole := range roleNames {
				if userRole.Name == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, dto.ErrorResponse{
				Message: "Required roles: " + strings.Join(roleNames, ", "),
				Code:    "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
