package service

import (
	"context"
	"fmt"
	"os"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/db"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/dto"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/repository"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type AuthService struct {
	userRepo *repository.UserRepository
	roleRepo *repository.RoleRepository
	keycloak *KeycloakClient
}

func NewAuthService(userRepo *repository.UserRepository, roleRepo *repository.RoleRepository, keycloak *KeycloakClient) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		roleRepo: roleRepo,
		keycloak: keycloak,
	}
}

// Login authenticates user with Keycloak and syncs with local database
func (s *AuthService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	// Authenticate with Keycloak
	tokenResp, err := s.keycloak.Login(req.Username, req.Password)
	if err != nil {
		logrus.WithError(err).Error("Keycloak login failed")
		return nil, fmt.Errorf("authentication failed")
	}

	// Validate token and get user info from Keycloak
	userInfo, err := s.keycloak.ValidateToken(tokenResp.AccessToken)
	if err != nil {
		logrus.WithError(err).Error("Failed to validate token")
		return nil, fmt.Errorf("token validation failed")
	}

	// Sync user with local database
	err = s.syncUserFromKeycloak(ctx, userInfo)
	if err != nil {
		logrus.WithError(err).Error("Failed to sync user from Keycloak")
		// Don't fail login if sync fails, just log the error
	}

	return &dto.LoginResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.LoginResponse, error) {
	// Check if user already exists in local database
	existingUser, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}
	if existingUser != nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Create user in Keycloak first
	keycloakUserID, err := s.keycloak.CreateUser(req.Username, req.Email, req.FirstName, req.LastName, req.Password)
	if err != nil {
		logrus.WithError(err).Error("Failed to create user in Keycloak")
		return nil, fmt.Errorf("failed to create user account")
	}

	// Create user in local database
	user := &db.User{
		Username:   req.Username,
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Enabled:    true,
		KeycloakID: keycloakUserID,
	}

	err = s.userRepo.CreateUser(ctx, user)
	if err != nil {
		logrus.WithError(err).Error("Failed to create user in database")
		// TODO: Consider rolling back Keycloak user creation
		return nil, fmt.Errorf("failed to create user record")
	}

	// Assign default role
	err = s.assignDefaultRole(ctx, user.ID)
	if err != nil {
		logrus.WithError(err).Error("Failed to assign default role")
		// Don't fail registration if role assignment fails
	}

	// Auto-login the user after registration
	loginResp, err := s.Login(ctx, &dto.LoginRequest{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		logrus.WithError(err).Error("Failed to auto-login after registration")
		// Registration succeeded, but auto-login failed
		return nil, fmt.Errorf("registration succeeded, please login manually")
	}

	logrus.Infof("Successfully registered user: %s", req.Username)
	return loginResp, nil
}

// GetCurrentUser retrieves current user info from token
func (s *AuthService) GetCurrentUser(ctx context.Context, accessToken string) (*dto.UserResponse, error) {
	// Validate token with Keycloak
	userInfo, err := s.keycloak.ValidateToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	// Get user from local database
	user, err := s.userRepo.GetUserByKeycloakID(ctx, userInfo.Sub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get user roles
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return s.userToDTO(user, roles), nil
}

// ValidateToken validates access token (for other microservices)
func (s *AuthService) ValidateToken(ctx context.Context, accessToken string) (*dto.UserResponse, error) {
	return s.GetCurrentUser(ctx, accessToken)
}

// syncUserFromKeycloak syncs user data from Keycloak to local database
func (s *AuthService) syncUserFromKeycloak(ctx context.Context, userInfo *KeycloakUserInfo) error {
	// Check if user exists in local database
	user, err := s.userRepo.GetUserByKeycloakID(ctx, userInfo.Sub)
	if err != nil {
		return fmt.Errorf("failed to get user by keycloak ID: %w", err)
	}

	if user == nil {
		// User doesn't exist in local database, create them
		user = &db.User{
			Username:   userInfo.PreferredUsername,
			Email:      userInfo.Email,
			FirstName:  userInfo.GivenName,
			LastName:   userInfo.FamilyName,
			Enabled:    true,
			KeycloakID: userInfo.Sub,
		}

		err = s.userRepo.CreateUser(ctx, user)
		if err != nil {
			return fmt.Errorf("failed to create user during sync: %w", err)
		}

		// Assign default role
		err = s.assignDefaultRole(ctx, user.ID)
		if err != nil {
			logrus.WithError(err).Error("Failed to assign default role during sync")
		}

		logrus.Infof("Synced new user from Keycloak: %s", user.Username)
	} else {
		// User exists, update their information if changed
		updated := false
		if user.Email != userInfo.Email {
			user.Email = userInfo.Email
			updated = true
		}
		if user.FirstName != userInfo.GivenName {
			user.FirstName = userInfo.GivenName
			updated = true
		}
		if user.LastName != userInfo.FamilyName {
			user.LastName = userInfo.FamilyName
			updated = true
		}

		if updated {
			err = s.userRepo.UpdateUser(ctx, user)
			if err != nil {
				return fmt.Errorf("failed to update user during sync: %w", err)
			}
			logrus.Infof("Updated user during sync: %s", user.Username)
		}
	}

	return nil
}

// assignDefaultRole assigns the default role to a user
func (s *AuthService) assignDefaultRole(ctx context.Context, userID uuid.UUID) error {
	defaultRoleName := os.Getenv("DEFAULT_USER_ROLE")
	if defaultRoleName == "" {
		logrus.Warn("DEFAULT_USER_ROLE not set, skipping role assignment")
		return nil
	}

	role, err := s.roleRepo.GetRoleByName(ctx, defaultRoleName)
	if err != nil {
		return fmt.Errorf("failed to get default role: %w", err)
	}
	if role == nil {
		return fmt.Errorf("default role '%s' not found", defaultRoleName)
	}

	err = s.userRepo.AssignRolesToUser(ctx, userID, []uuid.UUID{role.ID}, nil)
	if err != nil {
		return fmt.Errorf("failed to assign default role: %w", err)
	}

	return nil
}

// userToDTO converts database user and roles to DTO
func (s *AuthService) userToDTO(user *db.User, roles []*db.Role) *dto.UserResponse {
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
