# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cryptoscan ./cmd/cryptoscan

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates git

WORKDIR /app

COPY --from=builder /app/cryptoscan /usr/local/bin/cryptoscan

ENTRYPOINT ["cryptoscan"]
CMD ["--help"]
