package main

import (
	asaburu "asaburu/internal"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	buildOnlyFlag = flag.Bool("b", false, "Build only, don't start server.")
	outFlag       = flag.String("o", "public", "Folder for generated files.")
	addrFlag      = flag.String("addr", ":8080", "Server listen address.")
)

func main() {
	flag.Parse()
	isBuildOnly, outDir, addr := *buildOnlyFlag, *outFlag, *addrFlag

	tmpl := asaburu.NewTmpl()
	if err := tmpl.GenerateHTML(outDir); err != nil {
		log.Fatalf("failed to tmpl.GenerateHTML, Error: %v", err)
	}
	log.Printf("HTML files generated, dir: %s", outDir)
	if isBuildOnly {
		log.Println("Build Only, Exiting...")
		return
	}

	http.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	fs := http.FileServer(http.Dir(outDir))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("content-type", "application/wasm")
		}
		fs.ServeHTTP(w, r)
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on addr: [%s], Error: %v", addr, err)
		return
	}
	defer listener.Close()

	address := listener.Addr().String()
	log.Printf("Server is starting on [%s]", address)
	if err := http.Serve(listener, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("Server failed: %v", err)
	}
}
