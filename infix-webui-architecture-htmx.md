# Infix WebUI — Architectural Design (HTMX + Go)

## 1. Overview

This document describes the architecture of a web-based management interface for Infix, a network-focused immutable Linux OS. The WebUI provides operators with a graphical interface for configuration, monitoring, and troubleshooting of switches, routers, and edge devices.

The fundamental design principle: **the Go backend is a thin rendering layer between the browser and RESTCONF**. It fetches YANG data from the RESTCONF server, renders it into HTML templates, and returns fragments that HTMX swaps into the page. All configuration reads and writes go through RESTCONF — the Go backend never touches sysrepo, files, or daemons directly.

```
┌──────────────────────────────────────────────────────────┐
│                       Browser                            │
│                                                          │
│   ┌──────────────────────────────────────────────────┐   │
│   │  HTML page + htmx.js (~14KB)                     │   │
│   │                                                  │   │
│   │  hx-get="/interfaces"     → swap #content        │   │
│   │  hx-post="/interfaces/eth0/edit" → swap #form    │   │
│   │  hx-get="/api/counters"   → swap #counters       │   │
│   │         (hx-trigger="every 5s")                  │   │
│   └──────────────────────┬───────────────────────────┘   │
└──────────────────────────┼───────────────────────────────┘
                           │ HTTPS (HTML fragments)
                           │
┌──────────────────────────┼───────────────────────────────┐
│  Infix Device            │                               │
│                          ▼                               │
│  ┌───────────────────────────────────────────────────┐   │
│  │                  nginx                            │   │
│  │    TLS termination, static assets, proxy          │   │
│  │    /assets/*  → static files (CSS, JS, images)    │   │
│  │    /*         → Go backend :8080                  │   │
│  └──────────────────────┬────────────────────────────┘   │
│                         │                                │
│                         ▼                                │
│  ┌───────────────────────────────────────────────────┐   │
│  │              Go backend (infix-webui)             │   │
│  │                                                   │   │
│  │  ┌─────────────┐ ┌──────────┐ ┌───────────────┐  │   │
│  │  │  HTTP       │ │ Template │ │  RESTCONF     │  │   │
│  │  │  Handlers   │ │ Engine   │ │  Client       │  │   │
│  │  │             │ │ (html/   │ │               │  │   │
│  │  │  /login     │ │ template)│ │  GET/PATCH/   │  │   │
│  │  │  /dash      │ │          │ │  POST/DELETE  │  │   │
│  │  │  /ifaces    │ │ partials │ │               │  │   │
│  │  │  /routing   │ │ layouts  │ │  → localhost: │  │   │
│  │  │  /wifi      │ │          │ │     8090      │  │   │
│  │  │  /system    │ │          │ │  (rousette)   │  │   │
│  │  └─────────────┘ └──────────┘ └───────┬───────┘  │   │
│  └───────────────────────────────────────┼───────────┘   │
│                                          │               │
│                                          ▼               │
│  ┌───────────────────────────────────────────────────┐   │
│  │           rousette (RESTCONF server)              │   │
│  │           PAM authentication                      │   │
│  │           NACM authorization                      │   │
│  ├───────────────────────────────────────────────────┤   │
│  │           sysrepo datastore (YANG models)         │   │
│  ├───────────────────────────────────────────────────┤   │
│  │     system daemons (hostapd, frr, nftables, ...)  │   │
│  └───────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

## 2. Design Principles

**RESTCONF is the only data path.** The Go backend never reads config files, calls CLI tools, or accesses sysrepo directly. If the Go backend needs data, it GETs it from RESTCONF. If it needs to change something, it PATCHes RESTCONF. This guarantees that the WebUI, NETCONF clients, and automation scripts all see and change the same data through the same path.

**Server-rendered HTML, not JSON APIs.** The Go backend returns HTML fragments, not JSON. HTMX swaps these fragments into the DOM. There is no client-side state management, no virtual DOM, no JS build toolchain. The browser is a thin rendering target.

**Progressive enhancement.** Basic navigation works without JavaScript (full page loads via standard links). HTMX enhances the experience with partial page updates, inline editing, and live polling. If HTMX fails to load, the site still functions.

**Single static binary.** The Go backend compiles to one binary with embedded templates and static assets (`embed.FS`). No runtime dependencies beyond libc. Easy to package in Yocto, easy to deploy, easy to debug.

**Minimal resource footprint.** The Go binary idles at ~5-10 MB RSS. The browser downloads ~14KB of HTMX JS plus your CSS. No React, no Webpack, no node_modules.

## 3. Component Architecture

### 3.1 Go Backend Structure

```
infix-webui/
├── main.go                    # Entry point, server setup
├── go.mod
├── go.sum
│
├── internal/
│   ├── server/
│   │   ├── server.go          # HTTP server, middleware chain, router
│   │   └── middleware.go      # Auth, logging, security headers
│   │
│   ├── auth/
│   │   ├── session.go         # Session token management
│   │   ├── login.go           # Login/logout handlers
│   │   └── store.go           # In-memory session store
│   │
│   ├── restconf/
│   │   ├── client.go          # RESTCONF HTTP client
│   │   ├── errors.go          # RESTCONF error parsing
│   │   └── types.go           # Go structs for YANG data
│   │
│   ├── handlers/
│   │   ├── dashboard.go       # GET /
│   │   ├── interfaces.go      # GET/POST /interfaces, /interfaces/{name}
│   │   ├── routing.go         # GET/POST /routing
│   │   ├── wifi.go            # GET/POST /wifi
│   │   ├── firewall.go        # GET/POST /firewall
│   │   ├── vpn.go             # GET/POST /vpn
│   │   ├── services.go        # GET/POST /services
│   │   ├── containers.go      # GET/POST /containers
│   │   └── system.go          # GET/POST /system
│   │
│   └── models/
│       ├── interfaces.go      # Data structures for ietf-interfaces
│       ├── routing.go         # Data structures for ietf-routing
│       ├── system.go          # Data structures for ietf-system
│       └── ...
│
├── templates/
│   ├── layouts/
│   │   ├── base.html          # Full page shell (head, nav, footer)
│   │   └── sidebar.html       # Navigation sidebar partial
│   │
│   ├── pages/
│   │   ├── dashboard.html     # Full dashboard page
│   │   ├── interfaces.html    # Interface list page
│   │   ├── interface.html     # Single interface detail page
│   │   ├── routing.html       # Routing page
│   │   ├── wifi.html          # WiFi page
│   │   ├── firewall.html      # Firewall page
│   │   ├── system.html        # System page
│   │   └── login.html         # Login page (no sidebar)
│   │
│   ├── fragments/
│   │   ├── interface_row.html       # Single table row (for swap)
│   │   ├── interface_form.html      # Inline edit form
│   │   ├── interface_counters.html  # Live counter update
│   │   ├── route_table.html         # Route table body
│   │   ├── wifi_clients.html        # Connected clients list
│   │   ├── alert.html               # Toast/alert notification
│   │   └── confirm_dialog.html      # Confirmation modal
│   │
│   └── components/
│       ├── table.html         # Reusable table component
│       ├── form_field.html    # Form field with label + validation
│       ├── toggle.html        # On/off toggle
│       ├── status_badge.html  # Up/down/error badge
│       └── sparkline.html     # Inline traffic sparkline (SVG)
│
├── static/
│   ├── css/
│   │   └── style.css          # Single stylesheet (or Tailwind output)
│   ├── js/
│   │   ├── htmx.min.js        # HTMX library (~14KB)
│   │   └── app.js             # Minimal custom JS (if any)
│   └── img/
│       └── logo.svg
│
└── Makefile                   # Build targets
```

### 3.2 Request Flow

Every request follows the same pattern:

```
Browser request
    │
    ▼
nginx (TLS, static assets)
    │
    ▼
Go router (chi, stdlib mux, or gorilla)
    │
    ▼
Auth middleware
    │  ├── Check session cookie
    │  ├── Valid → attach user to context
    │  └── Invalid → redirect to /login (full page)
    │                or return 401 (HTMX request)
    ▼
Handler function
    │
    │  1. Parse request (path params, form values)
    │
    │  2. Call RESTCONF client
    │     GET /restconf/data/ietf-interfaces:interfaces
    │     (using the user's session credentials)
    │
    │  3. Map JSON response → Go struct
    │
    │  4. Execute template with struct as data
    │
    │  5. Return HTML
    │     ├── Full page (normal request / first load)
    │     └── Fragment (HTMX request, HX-Request header)
    │
    ▼
Browser
    ├── Full page → render entire page
    └── Fragment → HTMX swaps into target element
```

### 3.3 Full Page vs Fragment Detection

The Go backend serves both full-page loads (first visit, bookmark, refresh) and HTMX fragment requests from the same handler:

```go
func (h *InterfacesHandler) List(w http.ResponseWriter, r *http.Request) {
    // 1. Fetch data from RESTCONF
    ifaces, err := h.restconf.GetInterfaces(r.Context())
    if err != nil {
        h.renderError(w, r, err)
        return
    }

    data := InterfaceListData{
        Interfaces: ifaces,
        Title:      "Interfaces",
    }

    // 2. Detect HTMX request
    if r.Header.Get("HX-Request") == "true" {
        // Return only the content fragment
        h.render(w, "fragments/interface_list.html", data)
    } else {
        // Return full page with layout
        h.render(w, "pages/interfaces.html", data)
    }
}
```

This means every page is bookmarkable, works on refresh, and works without JavaScript — while HTMX users get smooth partial updates.

### 3.4 RESTCONF Client

The Go backend talks to rousette over localhost HTTP:

```go
// internal/restconf/client.go

type Client struct {
    baseURL    string            // http://127.0.0.1:8090/restconf
    httpClient *http.Client
}

// Get fetches a RESTCONF resource, passing through the user's credentials.
// The session middleware attaches credentials to the request context.
func (c *Client) Get(ctx context.Context, path string, target interface{}) error {
    url := c.baseURL + path

    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return err
    }

    req.Header.Set("Accept", "application/yang-data+json")

    // Forward user credentials from session
    creds := auth.CredentialsFromContext(ctx)
    req.SetBasicAuth(creds.Username, creds.Password)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("restconf request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return parseRestconfError(resp)
    }

    return json.NewDecoder(resp.Body).Decode(target)
}

// Patch sends a partial update to RESTCONF.
func (c *Client) Patch(ctx context.Context, path string, body interface{}) error {
    payload, err := json.Marshal(body)
    if err != nil {
        return err
    }

    req, err := http.NewRequestWithContext(ctx, "PATCH",
        c.baseURL+path, bytes.NewReader(payload))
    if err != nil {
        return err
    }

    req.Header.Set("Content-Type", "application/yang-data+json")

    creds := auth.CredentialsFromContext(ctx)
    req.SetBasicAuth(creds.Username, creds.Password)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        return parseRestconfError(resp)
    }
    return nil
}
```

**Important:** the Go backend forwards the user's credentials to rousette on every RESTCONF call. This means rousette's PAM authentication and NACM authorization work exactly as they do for any other RESTCONF client. The Go backend never authenticates as a privileged service account.

## 4. Authentication

### 4.1 Session Flow

```
Browser                    Go backend                   rousette (PAM)
  │                            │                             │
  │  GET /                     │                             │
  │───────────────────────────►│                             │
  │                            │ No session cookie           │
  │  302 → /login              │                             │
  │◄───────────────────────────│                             │
  │                            │                             │
  │  GET /login                │                             │
  │───────────────────────────►│                             │
  │  <login page HTML>         │                             │
  │◄───────────────────────────│                             │
  │                            │                             │
  │  POST /login               │                             │
  │  username=admin&pass=xxx   │                             │
  │───────────────────────────►│                             │
  │                            │  Verify credentials:        │
  │                            │  GET /restconf/data/        │
  │                            │    ietf-system:system       │
  │                            │  Authorization: Basic ...   │
  │                            │────────────────────────────►│
  │                            │                             │
  │                            │  200 OK (creds valid)       │
  │                            │◄────────────────────────────│
  │                            │                             │
  │                            │  Create session:            │
  │                            │  - Generate token           │
  │                            │  - Store: token → {user,    │
  │                            │    encrypted_pass, expiry}  │
  │                            │                             │
  │  302 → /                   │                             │
  │  Set-Cookie: session=token │                             │
  │  HttpOnly; Secure;         │                             │
  │  SameSite=Strict           │                             │
  │◄───────────────────────────│                             │
  │                            │                             │
  │  GET /                     │                             │
  │  Cookie: session=token     │                             │
  │───────────────────────────►│                             │
  │                            │  Look up session            │
  │                            │  Forward creds to rousette  │
  │                            │────────────────────────────►│
  │                            │  200 OK + data              │
  │                            │◄────────────────────────────│
  │  <dashboard HTML>          │                             │
  │◄───────────────────────────│                             │
```

### 4.2 Session Store

```go
// internal/auth/store.go

type Session struct {
    Username      string
    EncryptedPass []byte      // AES-encrypted, decrypted per-request
    CreatedAt     time.Time
    LastAccess    time.Time
}

type SessionStore struct {
    mu       sync.RWMutex
    sessions map[string]*Session   // token → session
    key      [32]byte              // AES key, random per boot
}

// NewSessionStore creates a store with a random encryption key.
// The key is lost on restart — all sessions invalidate, users re-login.
func NewSessionStore() *SessionStore {
    store := &SessionStore{
        sessions: make(map[string]*Session),
    }
    // Random key per boot — credentials never persist to disk
    rand.Read(store.key[:])

    // Start cleanup goroutine
    go store.cleanup()
    return store
}

// Create generates a new session after successful auth.
func (s *SessionStore) Create(username, password string) (string, error) {
    token := generateToken()   // 256-bit random, base64url

    encrypted, err := encrypt(s.key[:], []byte(password))
    if err != nil {
        return "", err
    }

    s.mu.Lock()
    s.sessions[token] = &Session{
        Username:      username,
        EncryptedPass: encrypted,
        CreatedAt:     time.Now(),
        LastAccess:    time.Now(),
    }
    s.mu.Unlock()

    return token, nil
}

// Lookup validates a token and returns credentials for RESTCONF calls.
func (s *SessionStore) Lookup(token string) (username, password string, ok bool) {
    s.mu.RLock()
    sess, exists := s.sessions[token]
    s.mu.RUnlock()

    if !exists {
        return "", "", false
    }

    // Check expiry
    if time.Since(sess.LastAccess) > 30*time.Minute {
        s.Delete(token)
        return "", "", false
    }
    if time.Since(sess.CreatedAt) > 8*time.Hour {
        s.Delete(token)
        return "", "", false
    }

    // Update last access (sliding expiry)
    s.mu.Lock()
    sess.LastAccess = time.Now()
    s.mu.Unlock()

    pass, err := decrypt(s.key[:], sess.EncryptedPass)
    if err != nil {
        return "", "", false
    }

    return sess.Username, string(pass), true
}

// cleanup removes expired sessions every minute.
func (s *SessionStore) cleanup() {
    ticker := time.NewTicker(1 * time.Minute)
    for range ticker.C {
        s.mu.Lock()
        for token, sess := range s.sessions {
            if time.Since(sess.LastAccess) > 30*time.Minute ||
                time.Since(sess.CreatedAt) > 8*time.Hour {
                delete(s.sessions, token)
            }
        }
        s.mu.Unlock()
    }
}
```

### 4.3 Why Store Encrypted Credentials in the Session?

The Go backend needs to forward the user's credentials to rousette on every RESTCONF call so that PAM auth and NACM authorization work per-user. The alternatives:

| Approach | Problem |
|---|---|
| Go backend uses a privileged service account | Bypasses NACM. Every user gets full access. |
| Go backend authenticates to rousette via token | Rousette doesn't have token auth — it has PAM. Would need changes to rousette. |
| Store plaintext password in session | If memory is dumped, all passwords are exposed. |
| **Encrypt password with per-boot key** | **Key only exists in process memory. Lost on restart. Reasonable trade-off.** |

The encrypted-credentials approach means the Go backend acts as a **transparent proxy** for authentication — rousette still does all the real auth and authz work via PAM/NACM.

### 4.4 Session Configuration

| Parameter | Value | Rationale |
|---|---|---|
| Token size | 256-bit random | Brute-force infeasible |
| Cookie flags | `HttpOnly`, `Secure`, `SameSite=Strict` | XSS can't read token, CSRF blocked |
| Cookie path | `/` | Whole site |
| Idle timeout | 30 minutes (sliding) | Re-login after inactivity |
| Absolute timeout | 8 hours | Force re-login after shift |
| Storage | In-memory only | Lost on restart — no disk persistence |
| Encryption | AES-256-GCM, random key per boot | Credentials not in plaintext in RAM |
| Concurrent sessions | Allowed (multiple tabs/devices) | Practical for operators |

## 5. HTMX Patterns

### 5.1 Page Navigation (Sidebar Links)

```html
<!-- templates/layouts/sidebar.html -->
<nav id="sidebar">
  <a href="/dashboard"
     hx-get="/dashboard"
     hx-target="#content"
     hx-push-url="true"
     class="nav-link">
    Dashboard
  </a>
  <a href="/interfaces"
     hx-get="/interfaces"
     hx-target="#content"
     hx-push-url="true"
     class="nav-link">
    Interfaces
  </a>
  <!-- ... -->
</nav>
```

`hx-push-url="true"` updates the browser URL bar, so bookmarks and back/forward work. The `href` fallback ensures the link works without JS.

### 5.2 Base Layout

```html
<!-- templates/layouts/base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Infix — {{.Title}}</title>
  <link rel="stylesheet" href="/assets/css/style.css">
  <script src="/assets/js/htmx.min.js"></script>
</head>
<body hx-boost="true">
  <div class="layout">
    {{template "sidebar.html" .}}

    <main id="content">
      {{block "content" .}}{{end}}
    </main>
  </div>

  <!-- Toast notifications target -->
  <div id="alerts" class="alerts-container"></div>
</body>
</html>
```

`hx-boost="true"` on the body automatically makes all links and forms use AJAX with history pushState — progressive enhancement with zero per-element configuration.

### 5.3 Interface List with Live Status

```html
<!-- templates/pages/interfaces.html -->
{{define "content"}}
<h1>Interfaces</h1>

<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Admin</th>
      <th>Oper</th>
      <th>IP Address</th>
      <th>Speed</th>
      <th>Traffic</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="interface-rows"
         hx-get="/fragments/interface-rows"
         hx-trigger="every 5s"
         hx-swap="innerHTML">
    {{range .Interfaces}}
    {{template "fragments/interface_row.html" .}}
    {{end}}
  </tbody>
</table>
{{end}}
```

```html
<!-- templates/fragments/interface_row.html -->
<tr id="iface-{{.Name}}">
  <td>
    <a href="/interfaces/{{.Name}}"
       hx-get="/interfaces/{{.Name}}"
       hx-target="#content"
       hx-push-url="true">
      {{.Name}}
    </a>
  </td>
  <td>{{if .Enabled}}
    <span class="badge badge-on">up</span>
  {{else}}
    <span class="badge badge-off">down</span>
  {{end}}</td>
  <td>{{if eq .OperStatus "up"}}
    <span class="badge badge-on">up</span>
  {{else}}
    <span class="badge badge-down">down</span>
  {{end}}</td>
  <td>{{.IPv4Address}}/{{.PrefixLength}}</td>
  <td>{{.Speed}}</td>
  <td>
    <span class="counter">↓{{.RxBytes | humanBytes}}</span>
    <span class="counter">↑{{.TxBytes | humanBytes}}</span>
  </td>
  <td>
    <button hx-get="/interfaces/{{.Name}}/edit"
            hx-target="#iface-{{.Name}}"
            hx-swap="outerHTML"
            class="btn-sm">
      Edit
    </button>
  </td>
</tr>
```

The table body polls every 5 seconds for updated interface rows. This is the HTMX equivalent of live-updating counters — no WebSocket, no SSE wiring, just a periodic GET that returns HTML.

### 5.4 Inline Editing

```html
<!-- templates/fragments/interface_form.html -->
<!-- Returned by GET /interfaces/{name}/edit -->
<tr id="iface-{{.Name}}" class="editing">
  <td>{{.Name}}</td>
  <td>
    <label class="toggle">
      <input type="checkbox" name="enabled" {{if .Enabled}}checked{{end}}>
    </label>
  </td>
  <td colspan="3">
    <input type="text" name="description" value="{{.Description}}"
           placeholder="Description">
    <input type="text" name="ipv4-address" value="{{.IPv4Address}}"
           placeholder="IP address" pattern="[\d.]+">
    /
    <input type="number" name="prefix-length" value="{{.PrefixLength}}"
           min="0" max="32" style="width:4em">
  </td>
  <td>
    <button hx-put="/interfaces/{{.Name}}"
            hx-include="closest tr"
            hx-target="#iface-{{.Name}}"
            hx-swap="outerHTML"
            class="btn-sm btn-primary">
      Save
    </button>
    <button hx-get="/fragments/interface-row/{{.Name}}"
            hx-target="#iface-{{.Name}}"
            hx-swap="outerHTML"
            class="btn-sm">
      Cancel
    </button>
  </td>
</tr>
```

Click Edit → row transforms into a form (fragment swap). Save → PUT to Go backend → PATCH to RESTCONF → return updated row fragment. Cancel → swap back to read-only row. No page navigation, no modals, no JavaScript state management.

### 5.5 Form Submission with Feedback

```html
<!-- Generic pattern: form that shows result inline -->
<form hx-post="/wifi/radio/wlan0"
      hx-target="#wifi-result"
      hx-swap="innerHTML"
      hx-indicator="#wifi-spinner">

  <!-- form fields -->
  <select name="channel">
    <option value="auto">Auto</option>
    {{range .AvailableChannels}}
    <option value="{{.}}" {{if eq . $.CurrentChannel}}selected{{end}}>
      {{.}}
    </option>
    {{end}}
  </select>

  <button type="submit">
    Apply
    <span id="wifi-spinner" class="htmx-indicator spinner"></span>
  </button>
</form>

<div id="wifi-result"></div>
```

The Go handler returns either a success alert fragment or an error fragment with details from the RESTCONF error response:

```html
<!-- templates/fragments/alert.html -->
<div class="alert alert-{{.Level}}" role="alert">
  {{.Message}}
</div>
```

### 5.6 Confirmation for Dangerous Actions

```html
<button hx-delete="/interfaces/br0"
        hx-confirm="Delete bridge br0? This will disconnect all member ports."
        hx-target="#iface-br0"
        hx-swap="outerHTML swap:0.5s"
        class="btn-sm btn-danger">
  Delete
</button>
```

HTMX's built-in `hx-confirm` shows a browser confirm dialog. For a nicer UX, use a custom confirmation modal pattern with `hx-get` to load a confirm dialog fragment.

### 5.7 SSE for Real-Time Updates (Optional)

If you want faster updates than polling for specific events:

```html
<!-- Live log viewer -->
<div hx-ext="sse"
     sse-connect="/events/log"
     sse-swap="message"
     hx-target="#log-entries"
     hx-swap="afterbegin">
</div>

<div id="log-entries">
  <!-- new log lines appear here -->
</div>
```

The Go backend subscribes to rousette's YANG notification stream (if available) and re-emits as SSE with pre-rendered HTML fragments:

```go
func (h *EventHandler) LogStream(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")

    flusher := w.(http.Flusher)

    for {
        select {
        case entry := <-h.logChan:
            html := h.renderFragment("fragments/log_entry.html", entry)
            fmt.Fprintf(w, "data: %s\n\n", html)
            flusher.Flush()
        case <-r.Context().Done():
            return
        }
    }
}
```

## 6. Handler Implementation Example

```go
// internal/handlers/interfaces.go

type InterfacesHandler struct {
    restconf  *restconf.Client
    templates *template.Template
}

func (h *InterfacesHandler) List(w http.ResponseWriter, r *http.Request) {
    var result struct {
        Interfaces struct {
            Interface []models.Interface `json:"interface"`
        } `json:"ietf-interfaces:interfaces"`
    }

    err := h.restconf.Get(r.Context(),
        "/data/ietf-interfaces:interfaces", &result)
    if err != nil {
        h.renderError(w, r, err)
        return
    }

    // Enrich with operational state
    for i := range result.Interfaces.Interface {
        iface := &result.Interfaces.Interface[i]
        h.enrichOperState(r.Context(), iface)
    }

    data := map[string]interface{}{
        "Title":      "Interfaces",
        "Interfaces": result.Interfaces.Interface,
    }

    if isHTMX(r) {
        h.render(w, "pages/interfaces.html#content", data)
    } else {
        h.renderFull(w, "pages/interfaces.html", data)
    }
}

func (h *InterfacesHandler) Update(w http.ResponseWriter, r *http.Request) {
    name := chi.URLParam(r, "name")

    // Parse form values
    r.ParseForm()
    patch := map[string]interface{}{
        "ietf-interfaces:interface": map[string]interface{}{
            "name":        name,
            "enabled":     r.FormValue("enabled") == "on",
            "description": r.FormValue("description"),
        },
    }

    err := h.restconf.Patch(r.Context(),
        "/data/ietf-interfaces:interfaces/interface="+name, patch)
    if err != nil {
        h.renderAlert(w, "error", "Failed to update: "+err.Error())
        return
    }

    // Return updated row fragment
    iface := h.fetchInterface(r.Context(), name)
    h.render(w, "fragments/interface_row.html", iface)
}

func isHTMX(r *http.Request) bool {
    return r.Header.Get("HX-Request") == "true"
}
```

## 7. nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate     /etc/ssl/certs/infix.pem;
    ssl_certificate_key /etc/ssl/private/infix.key;

    # Security headers
    add_header Content-Security-Policy
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # Static assets (served by nginx directly, not Go)
    location /assets/ {
        alias /var/www/infix/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Everything else → Go backend
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;

        # SSE support
        proxy_set_header Connection '';
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }

    # Rate limit login attempts
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    location = /login {
        limit_req zone=login burst=3;
        proxy_pass http://127.0.0.1:8080;
    }
}

server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

**Alternative: skip nginx entirely.** The Go binary can serve TLS directly with `http.ListenAndServeTLS`. This eliminates a dependency and simplifies the stack. Worth considering for devices where nginx is not already present. The trade-off is losing nginx's battle-tested TLS implementation, rate limiting, and static file serving performance — but for a management interface with a handful of concurrent users, Go's stdlib is more than adequate.

## 8. Build and Deployment

### 8.1 Embedded Assets

```go
// main.go
import "embed"

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS
```

Everything compiles into a single binary. No external file dependencies at runtime.

### 8.2 Build

```makefile
# Makefile

BINARY    = infix-webui
GOARCH   ?= arm64
GOOS     ?= linux

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	go build -ldflags="-s -w" -o $(BINARY) .

.PHONY: dev
dev:
	go run . -restconf http://192.168.1.1:8090/restconf -listen :8080
```

`CGO_ENABLED=0` produces a fully static binary. `-ldflags="-s -w"` strips debug info for a smaller binary (typically 5-15 MB for a project like this).

### 8.3 Yocto Recipe

```bitbake
# recipes-webui/infix-webui/infix-webui.bb
SUMMARY = "Infix Web Management Interface"
LICENSE = "..."

SRC_URI = "git://github.com/kernelkit/infix-webui.git;branch=main;protocol=https"

inherit go-mod

GO_IMPORT = "github.com/kernelkit/infix-webui"

CGO_ENABLED = "0"
GO_LDFLAGS = "-s -w"

do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${B}/infix-webui ${D}${sbindir}/

    # If serving static assets separately via nginx:
    install -d ${D}/var/www/infix/static
    cp -r ${S}/static/* ${D}/var/www/infix/static/
}

FILES:${PN} = "${sbindir}/infix-webui /var/www/infix"
```

### 8.4 Systemd Unit

```ini
# infix-webui.service
[Unit]
Description=Infix Web Management Interface
After=network.target rousette.service
Requires=rousette.service

[Service]
Type=simple
ExecStart=/usr/sbin/infix-webui \
    -listen 127.0.0.1:8080 \
    -restconf http://127.0.0.1:8090/restconf
Restart=on-failure
RestartSec=5
MemoryMax=32M

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/

[Install]
WantedBy=multi-user.target
```

## 9. Page Structure

```
┌─ Login (/login)
│   └── Username/password form, no sidebar
│
┌─ Dashboard (/)
│   ├── System: hostname, model, firmware version, uptime
│   ├── Resource gauges: CPU, RAM, flash usage
│   ├── Interface summary table with link status
│   └── Recent log entries (last 10)
│
├─ Interfaces (/interfaces)
│   ├── Table: name, admin/oper state, IP, speed, counters
│   ├── Inline edit (HTMX swap)
│   ├── Detail view (/interfaces/{name})
│   │   ├── Configuration form
│   │   ├── VLAN membership
│   │   ├── Counters (polled)
│   │   └── Traffic graph (SVG sparkline or chart)
│   └── Bridge/LAG management
│
├─ Routing (/routing)
│   ├── Static routes (add/edit/delete)
│   ├── OSPF status (if enabled)
│   └── Active routing table (operational state)
│
├─ Firewall (/firewall)
│   ├── Rule chains
│   ├── NAT rules
│   └── Per-rule hit counters
│
├─ WiFi (/wifi)
│   ├── Radio config (channel, txpower, regulatory)
│   ├── SSID/BSS management
│   └── Connected clients (polled)
│
├─ VPN (/vpn)
│   ├── WireGuard tunnels
│   └── Peer status (latest handshake, transfer)
│
├─ Services (/services)
│   ├── DHCP (server/relay config, leases)
│   ├── DNS
│   ├── NTP
│   ├── LLDP (neighbor table)
│   └── SNMP (when available)
│
├─ Containers (/containers)
│   ├── Running containers
│   └── Image management
│
└─ System (/system)
    ├── General (hostname, DNS, NTP)
    ├── Users
    ├── Firmware (active/standby, upgrade)
    ├── Configuration (save/load/factory-reset)
    ├── Certificates
    └── Log viewer (polled or SSE)
```

## 10. Summary

| Aspect | Decision |
|---|---|
| Architecture | Server-rendered HTML + HTMX |
| Backend | Go, single static binary |
| Templates | Go `html/template`, embedded via `embed.FS` |
| Frontend JS | htmx.min.js (~14KB) + minimal custom JS |
| Data access | All reads/writes via RESTCONF to rousette |
| Authentication | PAM (via rousette), session cookies in Go |
| Session storage | In-memory, encrypted credentials, per-boot key |
| Authorization | NACM in rousette (user creds forwarded per-request) |
| Live updates | HTMX polling (`hx-trigger="every 5s"`), optional SSE |
| TLS | nginx (or Go stdlib if nginx not desired) |
| Deployment | Single binary + systemd unit in Yocto image |
| Resource footprint | ~5-10 MB RSS (Go process), ~14KB JS (browser) |
| Progressive enhancement | Works without JS (full page loads), enhanced with HTMX |
| New daemons | One (infix-webui), or zero if embedded into rousette |
