package restconf

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Credentials holds username/password for Basic Auth.
// Stored in request contexts by the auth middleware.
type Credentials struct {
	Username string
	Password string
}

type ctxKey struct{}

// ContextWithCredentials returns a child context carrying creds.
func ContextWithCredentials(ctx context.Context, c Credentials) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// CredentialsFromContext extracts credentials set by the auth middleware.
func CredentialsFromContext(ctx context.Context) Credentials {
	c, _ := ctx.Value(ctxKey{}).(Credentials)
	return c
}

// Client talks to the rousette RESTCONF server.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a RESTCONF client pointing at baseURL
// (e.g. "http://127.0.0.1:8090/restconf").
// TLS verification is skipped because rousette typically uses a
// self-signed certificate on localhost.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: escapeZoneID(baseURL),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

// Get fetches a RESTCONF resource, decoding the JSON response into target.
// User credentials are taken from the request context (set by auth middleware).
func (c *Client) Get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/yang-data+json")

	creds := CredentialsFromContext(ctx)
	req.SetBasicAuth(creds.Username, creds.Password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("restconf request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return parseError(resp)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// CheckAuth verifies that the given credentials are accepted by rousette.
// It does a simple GET against /data/ietf-system:system with Basic Auth.
func (c *Client) CheckAuth(username, password string) error {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		c.baseURL+"/data/ietf-system:system",
		nil,
	)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/yang-data+json")
	req.SetBasicAuth(username, password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("restconf request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return parseError(resp)
	}

	return nil
}

// escapeZoneID replaces bare "%" in IPv6 zone IDs with "%25" so that
// Go's url.Parse doesn't reject them as invalid percent-encoding.
// e.g. "https://[ff02::1%qtap1]/restconf" → "https://[ff02::1%25qtap1]/restconf"
func escapeZoneID(rawURL string) string {
	open := strings.Index(rawURL, "[")
	close := strings.Index(rawURL, "]")
	if open < 0 || close < 0 || close < open {
		return rawURL
	}

	host := rawURL[open:close]
	if pct := strings.Index(host, "%"); pct >= 0 && !strings.HasPrefix(host[pct:], "%25") {
		return rawURL[:open+pct] + "%25" + rawURL[open+pct+1:]
	}
	return rawURL
}
