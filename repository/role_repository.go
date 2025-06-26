package repository

import (
	"context"
	"fmt"

	"github.com/SoumyadipBhowmik/user-management-keycloak-service/driver"
	"github.com/SoumyadipBhowmik/user-management-keycloak-service/models/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RoleRepository struct {
	DB *driver.DB
}

func NewRoleRepository(db *driver.DB) *RoleRepository {
	return &RoleRepository{DB: db}
}

// CreateRole creates a new role
func (r *RoleRepository) CreateRole(ctx context.Context, role *db.Role) error {
	query := `
		INSERT INTO roles (name)
		VALUES ($1)
		RETURNING id, created_at, updated_at`

	err := r.DB.Pool.QueryRow(ctx, query, role.Name).Scan(
		&role.ID, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// GetRoleByName retrieves role by name
func (r *RoleRepository) GetRoleByName(ctx context.Context, name string) (*db.Role, error) {
	query := `
		SELECT id, name, created_at, updated_at
		FROM roles 
		WHERE name = $1`

	var role db.Role
	err := r.DB.Pool.QueryRow(ctx, query, name).Scan(
		&role.ID, &role.Name, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}

	return &role, nil
}

// GetRoleByID retrieves role by ID
func (r *RoleRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*db.Role, error) {
	query := `
		SELECT id, name, created_at, updated_at
		FROM roles 
		WHERE id = $1`

	var role db.Role
	err := r.DB.Pool.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.Name, &role.CreatedAt, &role.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
	}

	return &role, nil
}

// GetAllRoles retrieves all roles
func (r *RoleRepository) GetAllRoles(ctx context.Context) ([]*db.Role, error) {
	query := `
		SELECT id, name, created_at, updated_at
		FROM roles 
		ORDER BY name`

	rows, err := r.DB.Pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
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

// UpdateRole updates role information
func (r *RoleRepository) UpdateRole(ctx context.Context, role *db.Role) error {
	query := `
		UPDATE roles 
		SET name = $2, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING updated_at`

	err := r.DB.Pool.QueryRow(ctx, query, role.ID, role.Name).Scan(&role.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

// DeleteRole deletes role by ID
func (r *RoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM roles WHERE id = $1`

	cmdTag, err := r.DB.Pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// GetRolesByNames retrieves multiple roles by their names
func (r *RoleRepository) GetRolesByNames(ctx context.Context, names []string) ([]*db.Role, error) {
	if len(names) == 0 {
		return []*db.Role{}, nil
	}

	query := `
		SELECT id, name, created_at, updated_at
		FROM roles 
		WHERE name = ANY($1)
		ORDER BY name`

	rows, err := r.DB.Pool.Query(ctx, query, names)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
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
