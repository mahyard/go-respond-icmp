# syntax=docker/dockerfile:1

# Build the application from source
FROM golang:1.24.2 AS build-stage

# Set destination for COPY
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y libnetfilter-queue-dev && \
    apt-get clean

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/reference/dockerfile/#copy
COPY *.go ./

# Build
RUN CGO_ENABLED=1 GOOS=linux go build -o /go-respond-icmp

# Deploy the application binary into a lean image
FROM alpine:3.20 AS build-release-stage

WORKDIR /

# Install the required runtime libraries
RUN apk add --no-cache libnetfilter_queue libc6-compat

COPY --from=build-stage /go-respond-icmp .

# Set the entrypoint to the application binary
ENTRYPOINT ["/go-respond-icmp"]
