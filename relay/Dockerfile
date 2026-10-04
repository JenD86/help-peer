FROM golang:1.18-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o relay-server .

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/relay-server .
RUN mkdir -p /data
ENV RELAY_DIR=/data
EXPOSE 7000
ENTRYPOINT ["/app/relay-server"]
