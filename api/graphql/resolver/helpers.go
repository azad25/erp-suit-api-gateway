package resolver

import (
	"erp-api-gateway/api/graphql/helpers"
	"erp-api-gateway/api/graphql/model"
	authpb "erp-api-gateway/proto/gen/auth"
)

// convertProtoUserToGraphQL converts a protobuf User to a GraphQL User model
func convertProtoUserToGraphQL(protoUser *authpb.User) *model.User {
	return helpers.ConvertProtoUserToGraphQL(protoUser)
}