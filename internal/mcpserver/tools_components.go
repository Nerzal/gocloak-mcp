package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listComponentsInput struct {
	realmInput
	Name         string `json:"name,omitempty" jsonschema:"optional component name filter"`
	ProviderType string `json:"type,omitempty" jsonschema:"optional provider type filter (e.g. org.keycloak.storage.UserStorageProvider)"`
	ParentID     string `json:"parent,omitempty" jsonschema:"optional parent ID filter"`
}

type componentIDInput struct {
	realmInput
	ComponentID string `json:"componentId" jsonschema:"Keycloak component UUID"`
}

type componentsOutput struct {
	Components []keycloak.ComponentInfo `json:"components"`
}

func registerComponentTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_components",
		Description: "List realm components such as LDAP/Kerberos user federation providers (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listComponentsInput) (*mcp.CallToolResult, any, error) {
		filter := keycloak.ComponentFilter{Name: in.Name, ProviderType: in.ProviderType, ParentID: in.ParentID}
		return executeTool(ctx, deps, "list_components", func(rCtx context.Context) (componentsOutput, error) {
			components, callErr := deps.service.ListComponents(rCtx, in.Realm, filter)
			return componentsOutput{Components: components}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_component",
		Description: "Get safe metadata for a single realm component by UUID (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in componentIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_component", func(rCtx context.Context) (keycloak.ComponentInfo, error) {
			res, callErr := deps.service.GetComponent(rCtx, in.Realm, in.ComponentID)
			return res, sanitizeErr(callErr)
		})
	})
}
