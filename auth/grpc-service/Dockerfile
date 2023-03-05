FROM golang:1.20.1-alpine3.17 AS builder
# RUN apk update && apk upgrade && apk add --no-cache git
WORKDIR /grpc-service
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build

FROM gcr.io/distroless/static-debian11:latest
COPY --from=builder ./grpc-service/grpc-service ./grpc-service
EXPOSE 9001
CMD ["./grpc-service"]
