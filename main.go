package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"

	"github.com/kernelkit/infix-webui/internal/auth"
	"github.com/kernelkit/infix-webui/internal/restconf"
	"github.com/kernelkit/infix-webui/internal/server"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	restconfURL := flag.String("restconf", "https://[fe80::ff:fe00:1%qtap1]/restconf", "RESTCONF base URL")
	flag.Parse()

	store, err := auth.NewSessionStore()
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
