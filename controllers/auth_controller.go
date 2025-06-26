package controllers

import (
	"net/http"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/dto"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthController struct {
	authService *service.AuthService
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{
		authService: authService,
	}
}

// Login handles user login
// @Summary User login
// @Description Authenticate user with Keycloak and return access token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} dto.LoginResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/login [post]
func (ctrl *AuthController) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Invalid request data",
			Code:    "INVALID_REQUEST",
		})
		return
	}

	response, err := ctrl.authService.Login(c.Request.Context(), &req)
	if err != nil {
		logrus.WithError(err).Error("Login failed")
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Message: "Invalid credentials",
			Code:    "INVALID_CREDENTIALS",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Register handles user registration
// @Summary User registration
// @Description Create new user account in Keycloak and local database
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterRequest true "Registration data"
// @Success 201 {object} dto.SuccessResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /auth/register [post]
func (ctrl *AuthController) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Invalid request data",
			Code:    "INVALID_REQUEST",
		})
		return
	}

	err := ctrl.authService.Register(c.Request.Context(), &req)
	if err != nil {
		logrus.WithError(err).Error("Registration failed")

		// Check if it's a duplicate user error
		if err.Error() == "username already exists" {
			c.JSON(http.StatusConflict, dto.ErrorResponse{
				Message: "Username already exists",
				Code:    "USERNAME_EXISTS",
			})
			return
		}

		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Registration failed",
			Code:    "REGISTRATION_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, dto.SuccessResponse{
		Message: "User registered successfully",
	})
}

// GetMe returns current user information
// @Summary Get current user
// @Description Get current authenticated user information
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.UserResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/me [get]
func (ctrl *AuthController) GetMe(c *gin.Context) {
	// Get user from context (set by auth middleware)
	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Message: "User not found",
			Code:    "USER_NOT_FOUND",
		})
		return
	}

	user, ok := userInterface.(*dto.UserResponse)
	if !ok {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Message: "Invalid user context",
			Code:    "INVALID_USER_CONTEXT",
		})
		return
	}

	c.JSON(http.StatusOK, user)
}

// ValidateToken validates access token (for other microservices)
// @Summary Validate token
// @Description Validate access token and return user info
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.UserResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/validate [get]
func (ctrl *AuthController) ValidateToken(c *gin.Context) {
	// Get access token from context
	tokenInterface, exists := c.Get("access_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Message: "Token not found",
			Code:    "TOKEN_NOT_FOUND",
		})
		return
	}

	token, ok := tokenInterface.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Message: "Invalid token context",
			Code:    "INVALID_TOKEN_CONTEXT",
		})
		return
	}

	user, err := ctrl.authService.ValidateToken(c.Request.Context(), token)
	if err != nil {
		logrus.WithError(err).Error("Token validation failed")
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Message: "Invalid token",
			Code:    "INVALID_TOKEN",
		})
		return
	}

	c.JSON(http.StatusOK, user)
}
