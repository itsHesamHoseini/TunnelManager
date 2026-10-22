FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=web /src/internal/ui/dist ./internal/ui/dist
ARG TARGETOS TARGETARCH
ARG VERSION=0.6.0
ARG COMMIT=development
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/itsHesamHoseini/TunnelManager/internal/buildinfo.Version=$VERSION -X github.com/itsHesamHoseini/TunnelManager/internal/buildinfo.Commit=$COMMIT" -o /out/tunnelmanager ./cmd/tunnelmanager
FROM scratch
LABEL org.opencontainers.image.title="TunnelManager" org.opencontainers.image.source="https://github.com/itsHesamHoseini/TunnelManager" org.opencontainers.image.licenses="MIT"
COPY --from=build /out/tunnelmanager /tunnelmanager
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/tunnelmanager"]
