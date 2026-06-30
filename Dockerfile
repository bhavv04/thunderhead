# ─── Stage 1: build ──────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build

WORKDIR /src

# Cache module downloads separately from source changes
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static binary, no CGO, stripped symbols for smaller size
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /thunderhead \
    ./cmd/thunderhead

# ─── Stage 2: run ────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    addgroup -S thunderhead && \
    adduser -S thunderhead -G thunderhead

WORKDIR /app

COPY --from=build /thunderhead .

# Config, state file, and logs persist outside the container via this volume
RUN mkdir -p /app/data && chown -R thunderhead:thunderhead /app
VOLUME ["/app/data"]

USER thunderhead

EXPOSE 8080

ENTRYPOINT ["./thunderhead"]
CMD ["--config=/app/data/config.json", "--state=/app/data/state.json"]