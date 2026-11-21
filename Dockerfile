FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/gocloak-mcp ./cmd/gocloak-mcp

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/Nerzal/gocloak-mcp" \
      org.opencontainers.image.description="Security-first, read-only Keycloak MCP server built in Go with GoCloak v15" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.modelcontextprotocol.server.name="io.github.Nerzal/gocloak-mcp"
COPY --from=build /out/gocloak-mcp /gocloak-mcp
USER nonroot:nonroot
ENTRYPOINT ["/gocloak-mcp"]
