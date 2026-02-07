package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/kernelkit/infix-webui/internal/auth"
	"github.com/kernelkit/infix-webui/internal/restconf"
	"github.com/kernelkit/infix-webui/internal/server"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
	defaultRC := "http://localhost:8080/restconf"
	if env := os.Getenv("RESTCONF_URL"); env != "" {
		defaultRC = env
	}

	listen := flag.String("listen", ":8080", "address to listen on")
	restconfURL := flag.String("restconf", defaultRC, "RESTCONF base URL")
	sessionKey := flag.String("session-key", "/var/lib/misc/webui-session.key", "path to persistent session key file")
	flag.Parse()

	store, err := auth.NewSessionStore(*sessionKey)
	if err != nil {
		log.Fatalf("session store: %v", err)
	}

	rc := restconf.NewClient(*restconfURL)

	tmplFS, err := fs.Sub(templateFS, "templates")
	if err != nil {
		log.Fatalf("template fs: %v", err)
	}

	stFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}

	handler, err := server.New(store, rc, tmplFS, stFS)
	if err != nil {
		log.Fatalf("server setup: %v", err)
	}

	log.Printf("listening on %s (restconf %s)", *listen, *restconfURL)
	if err := http.ListenAndServe(*listen, handler); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
