package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/driver"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type UserRepository struct {
	DB *driver.DB
}

func NewUserRepository(db *driver.DB) *UserRepository {
	return &UserRepository{DB: db}
}

// CreateUser creates a new user in the database
func (r *UserRepository) CreateUser(ctx context.Context, user *db.User) error {
	query := `
		INSERT INTO users (username, email, first_name, last_name, enabled, keycloak_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	err := r.DB.Pool.QueryRow(ctx, query,
		user.Username, user.Email, user.FirstName, user.LastName, user.Enabled, user.KeycloakID,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByUsername retrieves user by username
func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*db.User, error) {
	query := `
		SELECT id, username, email, first_name, last_name, enabled, keycloak_id, created_at, updated_at
		FROM users 
		WHERE username = $1`

	var user db.User
	err := r.DB.Pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName,
		&user.Enabled, &user.KeycloakID, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return &user, nil
}

// GetUserByKeycloakID retrieves user by Keycloak ID
func (r *UserRepository) GetUserByKeycloakID(ctx context.Context, keycloakID string) (*db.User, error) {
	query := `
		SELECT id, username, email, first_name, last_name, enabled, keycloak_id, created_at, updated_at
		FROM users 
		WHERE keycloak_id = $1`

	var user db.User
	err := r.DB.Pool.QueryRow(ctx, query, keycloakID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName,
		&user.Enabled, &user.KeycloakID, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by keycloak ID: %w", err)
	}

	return &user, nil
}

// GetUserByID retrieves user by ID
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*db.User, error) {
	query := `
		SELECT id, username, email, first_name, last_name, enabled, keycloak_id, created_at, updated_at
		FROM users 
		WHERE id = $1`

	var user db.User
	err := r.DB.Pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName,
		&user.Enabled, &user.KeycloakID, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetAllUsers retrieves all users with pagination
func (r *UserRepository) GetAllUsers(ctx context.Context, limit, offset int) ([]*db.User, error) {
	query := `
		SELECT id, username, email, first_name, last_name, enabled, keycloak_id, created_at, updated_at
		FROM users 
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.DB.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*db.User
	for rows.Next() {
		var user db.User
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName,
			&user.Enabled, &user.KeycloakID, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &user)
	}

	return users, nil
}

// UpdateUser updates user information
func (r *UserRepository) UpdateUser(ctx context.Context, user *db.User) error {
	query := `
		UPDATE users 
		SET username = $2, email = $3, first_name = $4, last_name = $5, enabled = $6, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING updated_at`

	err := r.DB.Pool.QueryRow(ctx, query,
		user.ID, user.Username, user.Email, user.FirstName, user.LastName, user.Enabled,
	).Scan(&user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// DeleteUser deletes user by ID
func (r *UserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	cmdTag, err := r.DB.Pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetUserRoles retrieves all roles for a user
func (r *UserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*db.Role, error) {
	query := `
		SELECT r.id, r.name, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name`

	rows, err := r.DB.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []*db.Role
	for rows.Next() {
		var role db.Role
		err := rows.Scan(&role.ID, &role.Name, &role.CreatedAt, &role.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

// AssignRolesToUser assigns multiple roles to a user
func (r *UserRepository) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	if len(roleIDs) == 0 {
		return nil
	}

	// Start transaction
	tx, err := r.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Remove existing roles
	_, err = tx.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to remove existing roles: %w", err)
	}

	// Insert new roles
	valueStrings := make([]string, len(roleIDs))
	valueArgs := make([]interface{}, 0, len(roleIDs)*3)

	for i, roleID := range roleIDs {
		valueStrings[i] = fmt.Sprintf("($%d, $%d, $%d)", i*3+1, i*3+2, i*3+3)
		valueArgs = append(valueArgs, userID, roleID, assignedBy)
	}

	query := fmt.Sprintf("INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES %s",
		strings.Join(valueStrings, ","))

	_, err = tx.Exec(ctx, query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to assign roles: %w", err)
	}

	return tx.Commit(ctx)
}
