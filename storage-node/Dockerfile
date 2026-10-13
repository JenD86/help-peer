FROM golang:1.27-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o storage-node .

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/storage-node .
RUN mkdir -p /data
ENV STORAGE_DIR=/data
ENV STORAGE_BACKEND=disk
EXPOSE 7001
ENTRYPOINT ["/app/storage-node"]
