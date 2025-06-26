package db

import (
	"time"

	"github.com/google/uuid"
)

type UserRole struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	RoleID     uuid.UUID  `json:"role_id" db:"role_id"`
	AssignedBy *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	AssignedAt time.Time  `json:"assigned_at" db:"assigned_at"`
}
