package controllers

import (
	"net/http"
	"strconv"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/dto"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UserController struct {
	userService *service.UserService
}

func NewUserController(userService *service.UserService) *UserController {
	return &UserController{
		userService: userService,
	}
}

// GetAllUsers returns list of all users (admin only)
// @Summary Get all users
// @Description Get list of all users with pagination (admin only)
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Limit" default(10)
// @Param offset query int false "Offset" default(0)
// @Success 200 {array} dto.UserResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Router /users [get]
func (ctrl *UserController) GetAllUsers(c *gin.Context) {
	// Parse query parameters
	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 10
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	users, err := ctrl.userService.GetAllUsers(c.Request.Context(), limit, offset)
	if err != nil {
		logrus.WithError(err).Error("Failed to get all users")
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Message: "Failed to retrieve users",
			Code:    "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, users)
}

// GetUserByID returns user by ID
// @Summary Get user by ID
// @Description Get user information by ID (admin only)
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} dto.UserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /users/{id} [get]
func (ctrl *UserController) GetUserByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Invalid user ID format",
			Code:    "INVALID_ID",
		})
		return
	}

	user, err := ctrl.userService.GetUserByID(c.Request.Context(), id)
	if err != nil {
		logrus.WithError(err).Error("Failed to get user by ID")

		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, dto.ErrorResponse{
				Message: "User not found",
				Code:    "USER_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Message: "Failed to retrieve user",
			Code:    "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateUserRoles updates user roles (admin only)
// @Summary Update user roles
// @Description Update roles assigned to a user (admin only)
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param request body dto.UpdateUserRolesRequest true "Role update data"
// @Success 200 {object} dto.SuccessResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /users/{id}/roles [put]
func (ctrl *UserController) UpdateUserRoles(c *gin.Context) {
	idStr := c.Param("id")
	userID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Invalid user ID format",
			Code:    "INVALID_ID",
		})
		return
	}

	var req dto.UpdateUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Invalid request data",
			Code:    "INVALID_REQUEST",
		})
		return
	}

	// Get current user (admin) from context
	currentUserInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Message: "User not found in context",
			Code:    "USER_NOT_FOUND",
		})
		return
	}

	currentUser, ok := currentUserInterface.(*dto.UserResponse)
	if !ok {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Message: "Invalid user context",
			Code:    "INVALID_USER_CONTEXT",
		})
		return
	}

	err = ctrl.userService.UpdateUserRoles(c.Request.Context(), userID, req.RoleNames, currentUser.ID)
	if err != nil {
		logrus.WithError(err).Error("Failed to update user roles")

		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, dto.ErrorResponse{
				Message: "User not found",
				Code:    "USER_NOT_FOUND",
			})
			return
		}

		if err.Error() == "some roles not found in database" {
			c.JSON(http.StatusBadRequest, dto.ErrorResponse{
				Message: "Some roles not found",
				Code:    "ROLES_NOT_FOUND",
			})
			return
		}

		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Message: "Failed to update user roles",
			Code:    "UPDATE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, dto.SuccessResponse{
		Message: "User roles updated successfully",
	})
}
