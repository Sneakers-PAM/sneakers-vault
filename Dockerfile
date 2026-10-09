# syntax=docker/dockerfile:1
# One build, several images:
#   docker build --target vault .         the vault service (also the default)
#   docker build --target workflow .      the workflow service and its purge job
#   docker build --target seed-catalog .  the built-in catalogue upsert, safe for any environment
#   docker build --target seed .          demo data, for development and test environments only
ARG GO_VERSION=1.26.9
FROM golang:${GO_VERSION} AS build
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/Bugs5382/go-buildinfo.Version=${VERSION} -X github.com/Bugs5382/go-buildinfo.Commit=${COMMIT}" -o /out/vault ./cmd/vault
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/Bugs5382/go-buildinfo.Version=${VERSION} -X github.com/Bugs5382/go-buildinfo.Commit=${COMMIT}" -o /out/workflow ./cmd/workflow
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/Bugs5382/go-buildinfo.Version=${VERSION} -X github.com/Bugs5382/go-buildinfo.Commit=${COMMIT}" -o /out/workflow-purge ./cmd/workflow-purge
RUN CGO_ENABLED=0 go build -o /out/seed ./cmd/seed
RUN CGO_ENABLED=0 go build -o /out/seed-catalog ./cmd/seed-catalog

# Demo data for development and test environments only. No service image
# ships the seeder.
FROM gcr.io/distroless/static:nonroot AS seed
COPY --from=build /out/seed /seed
COPY --from=build /src/migrations/vault /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/seed"]

# The built-in secret-type catalogue upsert. It holds no demo data, so it can
# run after every deploy in any environment.
FROM gcr.io/distroless/static:nonroot AS seed-catalog
COPY --from=build /out/seed-catalog /seed-catalog
USER nonroot:nonroot
ENTRYPOINT ["/seed-catalog"]

# The workflow service, plus the one-shot history purge for a scheduled job.
FROM gcr.io/distroless/static:nonroot AS workflow
COPY --from=build /out/workflow /workflow
COPY --from=build /out/workflow-purge /workflow-purge
COPY --from=build /src/migrations/workflow /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/workflow"]

# The vault service (default target).
FROM gcr.io/distroless/static:nonroot AS vault
COPY --from=build /out/vault /vault
COPY --from=build /src/migrations/vault /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/vault"]
