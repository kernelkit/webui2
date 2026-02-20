package handlers

import (
	"context"

	"github.com/kernelkit/infix-webui/internal/security"
)

func csrfToken(ctx context.Context) string {
	return security.TokenFromContext(ctx)
}
