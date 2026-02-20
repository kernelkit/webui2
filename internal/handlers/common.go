package handlers

import (
	"context"

	"github.com/kernelkit/infix-webui/internal/security"
)

// PageData is the base template data passed to every page.
type PageData struct {
	CsrfToken    string
	PageTitle    string
	ActivePage   string
	Capabilities *Capabilities
}

func csrfToken(ctx context.Context) string {
	return security.TokenFromContext(ctx)
}
