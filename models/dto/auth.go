package dto

type UpdateUserRolesRequest struct {
	RoleNames []string `json:"role_names" binding:"required"`
}
