package service

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/db"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/dto"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/repository"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UserService struct {
	userRepo *repository.UserRepository
	roleRepo *repository.RoleRepository
	keycloak *KeycloakClient
}

func NewUserService(userRepo *repository.UserRepository, roleRepo *repository.RoleRepository, keycloak *KeycloakClient) *UserService {
	return &UserService{
		userRepo: userRepo,
		roleRepo: roleRepo,
		keycloak: keycloak,
	}
}

func (s *UserService) GetAllUsers(ctx context.Context, limit, offset int) ([]*dto.UserResponse, error) {
	users, err := s.userRepo.GetAllUsers(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	userResponses := make([]*dto.UserResponse, len(users))
	for i, user := range users {
		roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to get roles for user %s", user.Username)
			roles = []*db.Role{}
		}

		userResponses[i] = s.userToDTO(user, roles)
	}

	return userResponses, nil
}

func (s *UserService) GetUserByID(ctx context.Context, id uuid.UUID) (*dto.UserResponse, error) {
	user, err := s.userRepo.GetUserByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return s.userToDTO(user, roles), nil
}

func (s *UserService) UpdateUserRoles(ctx context.Context, userID uuid.UUID, roleNames []string, assignedBy uuid.UUID) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	availableRoles := s.getAvailableRoles()
	for _, roleName := range roleNames {
		if !s.isValidRole(roleName, availableRoles) {
			return fmt.Errorf("invalid role: %s", roleName)
		}
	}

	roles, err := s.roleRepo.GetRolesByNames(ctx, roleNames)
	if err != nil {
		return fmt.Errorf("failed to get roles: %w", err)
	}

	if len(roles) != len(roleNames) {
		return fmt.Errorf("some roles not found in database")
	}

	roleIDs := make([]uuid.UUID, len(roles))
	for i, role := range roles {
		roleIDs[i] = role.ID
	}

	err = s.userRepo.AssignRolesToUser(ctx, userID, roleIDs, &assignedBy)
	if err != nil {
		return fmt.Errorf("failed to assign roles: %w", err)
	}

	logrus.Infof("Updated roles for user %s: %v", user.Username, roleNames)
	return nil
}

func (s *UserService) IsUserAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	roles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user roles: %w", err)
	}

	adminRole := os.Getenv("ADMIN_ROLE")
	if adminRole == "" {
		adminRole = "admin"
	}

	for _, role := range roles {
		if role.Name == adminRole {
			return true, nil
		}
	}

	return false, nil
}

func (s *UserService) IsUserInAdminList(ctx context.Context, keycloakID string) bool {
	adminUsers := os.Getenv("ADMIN_USERS")
	if adminUsers == "" {
		return false
	}

	adminUserList := strings.Split(adminUsers, ",")
	for _, adminUser := range adminUserList {
		if strings.TrimSpace(adminUser) == keycloakID {
			return true
		}
	}

	return false
}

func (s *UserService) GetCurrentUserFromToken(ctx context.Context, accessToken string) (*dto.UserResponse, error) {
	userInfo, err := s.keycloak.ValidateToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	user, err := s.userRepo.GetUserByKeycloakID(ctx, userInfo.Sub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return s.userToDTO(user, roles), nil
}

func (s *UserService) getAvailableRoles() []string {
	availableRoles := os.Getenv("AVAILABLE_ROLES")
	if availableRoles == "" {
		return []string{"player", "admin"}
	}
	return strings.Split(availableRoles, ",")
}

func (s *UserService) isValidRole(roleName string, availableRoles []string) bool {
	for _, role := range availableRoles {
		if strings.TrimSpace(role) == roleName {
			return true
		}
	}
	return false
}

func (s *UserService) userToDTO(user *db.User, roles []*db.Role) *dto.UserResponse {
	roleResponses := make([]dto.RoleResponse, len(roles))
	for i, role := range roles {
		roleResponses[i] = dto.RoleResponse{
			ID:   role.ID,
			Name: role.Name,
		}
	}

	return &dto.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Enabled:   user.Enabled,
		Roles:     roleResponses,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
