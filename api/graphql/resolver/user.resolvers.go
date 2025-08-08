package resolver

import (
	"context"

	"erp-api-gateway/api/graphql/model"
)

// User type resolvers
type userResolver struct{ *Resolver }

// Roles is the resolver for the User.roles field
func (r *userResolver) Roles(ctx context.Context, obj *model.User) ([]*model.Role, error) {
	if obj == nil {
		return []*model.Role{}, nil
	}

	// For now, return empty array since the auth service doesn't have GetUserRoles method yet
	// TODO: Implement proper user roles loading when the auth service supports it
	r.Logger.Info("User roles requested", map[string]interface{}{
		"user_id": obj.ID,
		"note":    "GetUserRoles method not implemented in auth service yet",
	})

	return []*model.Role{}, nil
}

// Permissions is the resolver for the User.permissions field
func (r *userResolver) Permissions(ctx context.Context, obj *model.User) ([]*model.Permission, error) {
	if obj == nil {
		return []*model.Permission{}, nil
	}

	// For now, return empty array since the auth service doesn't have GetUserPermissions method yet
	// TODO: Implement proper user permissions loading when the auth service supports it
	r.Logger.Info("User permissions requested", map[string]interface{}{
		"user_id": obj.ID,
		"note":    "GetUserPermissions method not implemented in auth service yet",
	})

	return []*model.Permission{}, nil
}
