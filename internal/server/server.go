package server

import (
	"html/template"
	"io/fs"
	"net/http"

	"github.com/kernelkit/infix-webui/internal/auth"
	"github.com/kernelkit/infix-webui/internal/handlers"
	"github.com/kernelkit/infix-webui/internal/restconf"
)

// New creates a fully wired http.Handler with all routes and middleware.
func New(
	store *auth.SessionStore,
	rc *restconf.Client,
	templateFS fs.FS,
	staticFS fs.FS,
) (http.Handler, error) {
	// Parse templates per page so each can define its own "content" block
	// without collisions.
	loginTmpl, err := template.ParseFS(templateFS, "pages/login.html")
	if err != nil {
		return nil, err
	}
	dashTmpl, err := template.ParseFS(templateFS, "layouts/*.html", "pages/dashboard.html")
	if err != nil {
		return nil, err
	}
	fwTmpl, err := template.ParseFS(templateFS, "layouts/*.html", "pages/firewall.html")
	if err != nil {
		return nil, err
	}
	ksTmpl, err := template.ParseFS(templateFS, "layouts/*.html", "pages/keystore.html")
	if err != nil {
		return nil, err
	}

	login := &auth.LoginHandler{
		Store:    store,
		RC:       rc,
		Template: loginTmpl,
	}

	dash := &handlers.DashboardHandler{
		Template: dashTmpl,
		RC:       rc,
	}

	fw := &handlers.FirewallHandler{
		Template: fwTmpl,
		RC:       rc,
	}

	ks := &handlers.KeystoreHandler{
		Template: ksTmpl,
		RC:       rc,
	}

	mux := http.NewServeMux()

	// Auth routes (public).
	mux.HandleFunc("GET /login", login.ShowLogin)
	mux.HandleFunc("POST /login", login.DoLogin)
	mux.HandleFunc("POST /logout", login.DoLogout)

	// Static assets (public).
	staticServer := http.FileServerFS(staticFS)
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", staticServer))

	// Authenticated routes.
	mux.HandleFunc("GET /{$}", dash.Index)
	mux.HandleFunc("GET /firewall", fw.Overview)
	mux.HandleFunc("GET /keystore", ks.Overview)

	return authMiddleware(store, mux), nil
}
