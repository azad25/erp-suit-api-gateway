package resolver

import (
	"erp-api-gateway/api/graphql/model"
	authpb "erp-api-gateway/proto"
	"erp-api-gateway/api/graphql/helpers"
)

// Helper functions for cursor management
func getStartCursor(edges []*model.UserEdge) *string {
	if len(edges) > 0 {
		return &edges[0].Cursor
	}
	return nil
}

func getEndCursor(edges []*model.UserEdge) *string {
	if len(edges) > 0 {
		return &edges[len(edges)-1].Cursor
	}
	return nil
}

func getStartCursorActivity(edges []*model.UserActivityEdge) *string {
	if len(edges) > 0 {
		return &edges[0].Cursor
	}
	return nil
}

func getEndCursorActivity(edges []*model.UserActivityEdge) *string {
	if len(edges) > 0 {
		return &edges[len(edges)-1].Cursor
	}
	return nil
}

func getStartCursorOrg(edges []*model.OrganizationEdge) *string {
	if len(edges) > 0 {
		return &edges[0].Cursor
	}
	return nil
}

func getEndCursorOrg(edges []*model.OrganizationEdge) *string {
	if len(edges) > 0 {
		return &edges[len(edges)-1].Cursor
	}
	return nil
}

func convertActivityUser(protoUser *authpb.User) *model.User {
	if protoUser != nil {
		return convertProtoUserToGraphQL(protoUser)
	}
	return nil
}

// convertProtoUserToGraphQL converts a protobuf User to a GraphQL User model
func convertProtoUserToGraphQL(protoUser *authpb.User) *model.User {
	return helpers.ConvertProtoUserToGraphQL(protoUser)
}

// convertProtoOrganizationToGraphQL converts a protobuf Organization to a GraphQL Organization model
func convertProtoOrganizationToGraphQL(protoOrg *authpb.Organization) *model.Organization {
	return helpers.ConvertProtoOrganizationToGraphQL(protoOrg)
}