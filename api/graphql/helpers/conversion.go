package helpers

import (
	"time"

	"erp-api-gateway/api/graphql/model"
	authpb "erp-api-gateway/proto"
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

	// Initialize empty roles and permissions for now
	// Roles will be loaded separately when needed
	user.Roles = []*model.Role{}

	// For now, permissions are handled through roles
	// If we need direct user permissions, we can add them here
	user.Permissions = []*model.Permission{}

	return user
}

// ConvertProtoOrganizationToGraphQL converts a protobuf Organization to a GraphQL Organization model
func ConvertProtoOrganizationToGraphQL(protoOrg *authpb.Organization) *model.Organization {
	if protoOrg == nil {
		return nil
	}

	org := &model.Organization{
		ID:              protoOrg.Id,
		Name:            protoOrg.Name,
		Domain:          protoOrg.Domain,
		IsActive:        protoOrg.IsActive,
		CreatedAt:       protoOrg.CreatedAt.AsTime().Format(time.RFC3339),
		UpdatedAt:       protoOrg.UpdatedAt.AsTime().Format(time.RFC3339),
		UserCount:       int(protoOrg.UserCount),
		ActiveUserCount: int(protoOrg.ActiveUserCount),
	}

	// Convert users if available
	if len(protoOrg.Users) > 0 {
		users := make([]*model.User, len(protoOrg.Users))
		for i, protoUser := range protoOrg.Users {
			users[i] = ConvertProtoUserToGraphQL(protoUser)
		}
		org.Users = users
	} else {
		org.Users = []*model.User{}
	}

	// Convert roles if available
	if len(protoOrg.Roles) > 0 {
		roles := make([]*model.Role, len(protoOrg.Roles))
		for i, protoRole := range protoOrg.Roles {
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
		org.Roles = roles
	} else {
		org.Roles = []*model.Role{}
	}

	// Initialize permissions as empty for now
	org.Permissions = []*model.Permission{}

	return org
}