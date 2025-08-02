package helpers

import (
	"time"

	"erp-api-gateway/api/graphql/model"
	authpb "erp-api-gateway/proto/gen/auth"
)

// ConvertProtoUserToGraphQL converts a protobuf User to a GraphQL User model
func ConvertProtoUserToGraphQL(protoUser *authpb.User) *model.User {
	user := &model.User{
		ID:        protoUser.Id,
		FirstName: protoUser.FirstName,
		LastName:  protoUser.LastName,
		Email:     protoUser.Email,
		CreatedAt: protoUser.CreatedAt.AsTime().Format(time.RFC3339),
		UpdatedAt: protoUser.UpdatedAt.AsTime().Format(time.RFC3339),
	}
	
	if protoUser.EmailVerifiedAt != nil {
		emailVerified := protoUser.EmailVerifiedAt.AsTime().Format(time.RFC3339)
		user.EmailVerifiedAt = &emailVerified
	}
	
	// Convert roles and permissions
	roles := make([]*model.Role, len(protoUser.Roles))
	for i, roleName := range protoUser.Roles {
		roles[i] = &model.Role{
			ID:   roleName,
			Name: roleName,
		}
	}
	user.Roles = roles
	
	permissions := make([]*model.Permission, len(protoUser.Permissions))
	for i, permName := range protoUser.Permissions {
		permissions[i] = &model.Permission{
			ID:   permName,
			Name: permName,
		}
	}
	user.Permissions = permissions
	
	return user
}