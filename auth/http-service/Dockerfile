FROM golang:1.20.2-alpine3.17 AS builder
# RUN apk update && apk upgrade && apk add --no-cache git
WORKDIR /http-service
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build

FROM gcr.io/distroless/static-debian11:latest
COPY --from=builder ./http-service/http-service ./http-service
EXPOSE 9002
CMD ["./http-service"]
