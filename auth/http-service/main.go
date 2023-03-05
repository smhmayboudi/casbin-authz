package main

import (
	"flag"
	"net/http"
	"strings"

	"github.com/casbin/casbin"
)

func rootHandler(w http.ResponseWriter, req *http.Request) {
	e := casbin.NewEnforcer("../casbin/model.conf", "../casbin/policy.csv")

	authorizations, ok := req.Header["Authorization"]
	if !ok {
		w.Header().Set("x-current-user", "")
		w.WriteHeader(http.StatusForbidden)

		return
	}

	extracted := strings.Fields(authorizations[0])
	if len(extracted) != 2 || extracted[0] != "Bearer" {
		w.Header().Set("x-current-user", "")
		w.WriteHeader(http.StatusForbidden)

		return
	}

	tokenStr := string(extracted[1][:])
	tokenvalue := strings.Split(tokenStr, ",")
	username := tokenvalue[1]
	path := req.URL.Path
	method := req.Method

	if !e.Enforce(path, username, method) {
		w.Header().Set("x-current-user", "")
		w.WriteHeader(http.StatusForbidden)

		return
	}

	w.Header().Set("x-current-user", username)
	w.WriteHeader(http.StatusOK)
}

func main() {
	addr := flag.String("addr", ":9002", "addr")
	flag.Parse()
	http.HandleFunc("/", rootHandler)
	http.ListenAndServe(*addr, nil)
}
