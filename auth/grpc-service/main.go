package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"

	"github.com/casbin/casbin"
	envoy_api_v3_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

type server struct {
}

var _ envoy_service_auth_v3.AuthorizationServer = (*server)(nil)

func New() *server {
	return &server{}
}

func (s *server) Check(ctx context.Context, req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	e := casbin.NewEnforcer("../casbin/model.conf", "../casbin/policy.csv")

	authorization, ok := req.Attributes.Request.Http.Headers["authorization"]
	if !ok {
		return &envoy_service_auth_v3.CheckResponse{
			Status: &status.Status{
				Code: int32(code.Code_PERMISSION_DENIED),
			},
		}, nil
	}

	extracted := strings.Fields(authorization)
	if len(extracted) != 2 || extracted[0] != "Bearer" {
		return &envoy_service_auth_v3.CheckResponse{
			Status: &status.Status{
				Code: int32(code.Code_PERMISSION_DENIED),
			},
		}, nil
	}

	tokenStr := string(extracted[1][:])
	tokenvalue := strings.Split(tokenStr, ",")
	username := tokenvalue[1]
	path := req.Attributes.Request.Http.Path
	method := req.Attributes.Request.Http.Method

	if !e.Enforce(path, username, method) {
		return &envoy_service_auth_v3.CheckResponse{
			Status: &status.Status{
				Code: int32(code.Code_PERMISSION_DENIED),
			},
		}, nil
	}

	return &envoy_service_auth_v3.CheckResponse{
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{
				Headers: []*envoy_api_v3_core.HeaderValueOption{
					{
						Append: &wrappers.BoolValue{Value: false},
						Header: &envoy_api_v3_core.HeaderValue{
							Key:   "x-current-user",
							Value: username,
						},
					},
				},
			},
		},
		Status: &status.Status{
			Code: int32(code.Code_OK),
		},
	}, nil
}

func main() {
	address := flag.String("address", ":9001", "address")
	flag.Parse()

	lis, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatalf("failed to listen to %s: %v", *address, err)
	}

	gs := grpc.NewServer()
	envoy_service_auth_v3.RegisterAuthorizationServer(gs, New())
	log.Printf("starting gRPC server on: %s\n", *address)
	gs.Serve(lis)
}
