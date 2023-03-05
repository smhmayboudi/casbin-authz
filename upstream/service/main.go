package main

import (
	"flag"
	"fmt"
	"net/http"
)

func serviceHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello\n")
	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func main() {
	addr := flag.String("addr", ":8080", "addr")
	flag.Parse()
	http.HandleFunc("/service", serviceHandler)
	http.ListenAndServe(*addr, nil)
}
