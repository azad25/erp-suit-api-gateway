package helpers

import (
	"time"

	"erp-api-gateway/api/graphql/model"
	authpb "erp-api-gateway/proto/gen/auth"
)

// ConvertProtoUserToGraphQL converts a protobuf User to a GraphQL User model
func ConvertProtoUserToGraphQL(protoUser *authpb.User) *model.User {
	if protoUser == nil {
		return nil
	}

	user := &model.User{
		ID:         protoUser.Id,
		FirstName:  protoUser.FirstName,
		LastName:   protoUser.LastName,
		Email:      protoUser.Email,
		IsActive:   protoUser.IsActive,
		IsVerified: protoUser.IsVerified,
		CreatedAt:  protoUser.CreatedAt.AsTime().Format(time.RFC3339),
		UpdatedAt:  protoUser.UpdatedAt.AsTime().Format(time.RFC3339),
	}

	// Set organization ID if available
	if protoUser.OrganizationId != "" {
		user.OrganizationID = &protoUser.OrganizationId
	}

	// Set last login time if available
	if protoUser.LastLoginAt != nil {
		lastLogin := protoUser.LastLoginAt.AsTime().Format(time.RFC3339)
		user.LastLoginAt = &lastLogin
	}

	// Convert organization if available
	if protoUser.Organization != nil {
		user.Organization = &model.Organization{
			ID:        protoUser.Organization.Id,
			Name:      protoUser.Organization.Name,
			Domain:    protoUser.Organization.Domain,
			IsActive:  protoUser.Organization.IsActive,
			CreatedAt: protoUser.Organization.CreatedAt.AsTime().Format(time.RFC3339),
			UpdatedAt: protoUser.Organization.UpdatedAt.AsTime().Format(time.RFC3339),
		}
	}

	// Convert roles if available
	if len(protoUser.Roles) > 0 {
		roles := make([]*model.Role, len(protoUser.Roles))
		for i, protoRole := range protoUser.Roles {
			role := &model.Role{
				ID:        protoRole.Id,
				Name:      protoRole.Name,
				IsSystem:  protoRole.IsSystem,
				IsActive:  protoRole.IsActive,
				CreatedAt: protoRole.CreatedAt.AsTime().Format(time.RFC3339),
				UpdatedAt: protoRole.UpdatedAt.AsTime().Format(time.RFC3339),
			}

			if protoRole.OrganizationId != "" {
				role.OrganizationID = &protoRole.OrganizationId
			}

			if protoRole.Description != "" {
				role.Description = &protoRole.Description
			}

			// Convert permissions for this role if available
			if len(protoRole.Permissions) > 0 {
				permissions := make([]*model.Permission, len(protoRole.Permissions))
				for j, protoPerm := range protoRole.Permissions {
					permission := &model.Permission{
						ID:        protoPerm.Id,
						Name:      protoPerm.Name,
						Resource:  protoPerm.Resource,
						Action:    protoPerm.Action,
						IsSystem:  protoPerm.IsSystem,
						CreatedAt: protoPerm.CreatedAt.AsTime().Format(time.RFC3339),
						UpdatedAt: protoPerm.UpdatedAt.AsTime().Format(time.RFC3339),
					}

					if protoPerm.Description != "" {
						permission.Description = &protoPerm.Description
					}

					if protoPerm.Scope != "" {
						permission.Scope = &protoPerm.Scope
					}

					permissions[j] = permission
				}
				role.Permissions = permissions
			} else {
				role.Permissions = []*model.Permission{}
			}

			roles[i] = role
		}
		user.Roles = roles
	} else {
		user.Roles = []*model.Role{}
	}

	// For now, permissions are handled through roles
	// If we need direct user permissions, we can add them here
	user.Permissions = []*model.Permission{}

	return user
}