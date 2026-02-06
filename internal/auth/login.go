package auth

import (
	"html/template"
	"log"
	"net/http"

	"github.com/kernelkit/infix-webui/internal/restconf"
)

const cookieName = "session"

// LoginHandler serves the login page and processes login/logout requests.
type LoginHandler struct {
	Store    *SessionStore
	RC       *restconf.Client
	Template *template.Template
}

// ShowLogin renders the login page (GET /login).
func (h *LoginHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	h.renderLogin(w, "")
}

// DoLogin validates credentials against RESTCONF and creates a session (POST /login).
func (h *LoginHandler) DoLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLogin(w, "Invalid request.")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.renderLogin(w, "Username and password are required.")
		return
	}

	// Verify credentials by making a RESTCONF call with Basic Auth.
	err := h.RC.CheckAuth(username, password)
	if err != nil {
		log.Printf("login failed for %q: %v", username, err)
		h.renderLogin(w, "Invalid username or password.")
		return
	}

	token, err := h.Store.Create(username, password)
	if err != nil {
		log.Printf("session create error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	fullRedirect(w, r, "/")
}

// DoLogout destroys the session and redirects to the login page (POST /logout).
func (h *LoginHandler) DoLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		h.Store.Delete(c.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	fullRedirect(w, r, "/login")
}

// fullRedirect forces a full page navigation.  When the request comes
// from htmx (boosted form) we use HX-Redirect so the browser does a
// real page load instead of an AJAX swap — this is essential for the
// login/logout transition where the page layout changes completely.
func fullRedirect(w http.ResponseWriter, r *http.Request, url string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", url)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (h *LoginHandler) renderLogin(w http.ResponseWriter, errMsg string) {
	data := map[string]string{"Error": errMsg}
	if err := h.Template.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
