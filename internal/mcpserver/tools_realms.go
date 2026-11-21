package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listEventsInput struct {
	realmInput
	pageInput
	Type     []string `json:"type,omitempty" jsonschema:"optional event types (e.g. LOGIN, LOGIN_ERROR)"`
	Client   string   `json:"client,omitempty" jsonschema:"optional clientId filter"`
	UserID   string   `json:"userId,omitempty" jsonschema:"optional user UUID filter"`
	DateFrom string   `json:"dateFrom,omitempty" jsonschema:"optional start date (YYYY-MM-DD)"`
	DateTo   string   `json:"dateTo,omitempty" jsonschema:"optional end date (YYYY-MM-DD)"`
}

type listAdminEventsInput struct {
	realmInput
	pageInput
	OperationTypes []string `json:"operationTypes,omitempty" jsonschema:"optional operation types (CREATE, UPDATE, DELETE, ACTION)"`
	ResourceTypes  []string `json:"resourceTypes,omitempty" jsonschema:"optional resource types (USER, CLIENT, ROLE, GROUP)"`
	ResourcePath   string   `json:"resourcePath,omitempty" jsonschema:"optional resource path filter"`
	DateFrom       string   `json:"dateFrom,omitempty" jsonschema:"optional start date (YYYY-MM-DD)"`
	DateTo         string   `json:"dateTo,omitempty" jsonschema:"optional end date (YYYY-MM-DD)"`
}

type realmsOutput struct {
	Realms []keycloak.RealmInfo `json:"realms"`
}

type eventsOutput struct {
	Events []keycloak.EventInfo `json:"events"`
}

type adminEventsOutput struct {
	Events []keycloak.AdminEventInfo `json:"events"`
}

func registerRealmTools(server *mcp.Server, deps toolDeps) {
	registerRealmInfoTools(server, deps)
	registerEventTools(server, deps)
}

func registerRealmInfoTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_realms",
		Description: "List accessible Keycloak realms permitted by KEYCLOAK_ALLOWED_REALMS.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_realms", func(rCtx context.Context) (realmsOutput, error) {
			realms, callErr := deps.service.ListRealms(rCtx)
			return realmsOutput{Realms: realms}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_realm_info",
		Description: "Get basic information about a configured Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_realm_info", func(rCtx context.Context) (keycloak.RealmInfo, error) {
			res, callErr := deps.service.GetRealmInfo(rCtx, in.Realm)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerEventTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_events",
		Description: "List login/user events in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listEventsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		filter := keycloak.EventFilter{
			Type: in.Type, Client: in.Client, UserID: in.UserID, DateFrom: in.DateFrom, DateTo: in.DateTo,
		}
		return executeTool(ctx, deps, "list_events", func(rCtx context.Context) (eventsOutput, error) {
			events, callErr := deps.service.ListEvents(rCtx, in.Realm, first, maxSize, &filter)
			return eventsOutput{Events: events}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_admin_events",
		Description: "List admin audit events in a Keycloak realm (without raw secret payloads).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listAdminEventsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		filter := keycloak.AdminEventFilter{
			OperationTypes: in.OperationTypes, ResourceTypes: in.ResourceTypes,
			ResourcePath: in.ResourcePath, DateFrom: in.DateFrom, DateTo: in.DateTo,
		}
		return executeTool(ctx, deps, "list_admin_events", func(rCtx context.Context) (adminEventsOutput, error) {
			events, callErr := deps.service.ListAdminEvents(rCtx, in.Realm, first, maxSize, &filter)
			return adminEventsOutput{Events: events}, sanitizeErr(callErr)
		})
	})
}
