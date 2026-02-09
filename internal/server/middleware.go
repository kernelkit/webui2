package server

import (
	"net/http"
	"strings"

	"github.com/kernelkit/infix-webui/internal/auth"
	"github.com/kernelkit/infix-webui/internal/restconf"
)

const cookieName = "session"

// authMiddleware checks the session cookie on every request, looks up
// the session, and attaches decrypted credentials to the context.
// Unauthenticated requests are redirected to /login (or get a 401 if
// the request comes from HTMX).
func authMiddleware(store *auth.SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(cookieName)
		if err != nil {
			deny(w, r)
			return
		}

		username, password, ok := store.Lookup(cookie.Value)
		if !ok {
			deny(w, r)
			return
		}

		// Sliding window: re-issue the cookie with a fresh timestamp.
		// Skip for background polling endpoints so they don't keep
		// the session alive indefinitely.
		if !isPollingPath(r.URL.Path) {
			if fresh, err := store.Create(username, password); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName,
					Value:    fresh,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}

		ctx := restconf.ContextWithCredentials(r.Context(), restconf.Credentials{
			Username: username,
			Password: password,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isPublicPath(path string) bool {
	return path == "/login" || strings.HasPrefix(path, "/assets/")
}

func isPollingPath(path string) bool {
	return path == "/device-status" || strings.HasSuffix(path, "/counters")
}

func deny(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
