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
	
	// The new User struct doesn't have EmailVerifiedAt field
	// Email verification status is now handled through the is_verified boolean field
	user.EmailVerifiedAt = nil
	
	// The new User struct doesn't have Roles field
	// Roles are now managed separately and can be retrieved via separate gRPC calls if needed
	user.Roles = []*model.Role{}
	
	// Permissions are now handled through role-based access control
	// and checked via the CheckPermission gRPC method when needed
	user.Permissions = []*model.Permission{}
	
	return user
}