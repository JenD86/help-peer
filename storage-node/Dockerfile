FROM golang:1.18-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o storage-node .

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/storage-node .
RUN mkdir -p /data
ENV STORAGE_DIR=/data
ENV STORAGE_BACKEND=disk
EXPOSE 7001
ENTRYPOINT ["/app/storage-node"]
