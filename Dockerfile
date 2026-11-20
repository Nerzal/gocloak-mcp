FROM golang:1.27.4-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keycloak-mcp ./cmd/keycloak-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keycloak-mcp /keycloak-mcp
USER nonroot:nonroot
ENTRYPOINT ["/keycloak-mcp"]
