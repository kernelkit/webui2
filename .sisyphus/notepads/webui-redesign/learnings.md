# CSS Redesign Learnings

- **Two-Layer Token System**: Successfully implemented a primitive/semantic token system. Primitives (slate-50, blue-500) are defined in `:root`, and semantics (bg, fg, primary) map to them. This makes dark mode implementation trivial by remapping semantics in `@media (prefers-color-scheme: dark)`.
- **Sidebar Persistence**: The sidebar needed to stay dark regardless of the theme. This was achieved by defining specific `--sidebar-*` variables that map to dark primitives (slate-800) in the default `:root` and do *not* change in the dark media query.
- **Component Preservation**: Legacy components like `.info-card h2` needed specific overrides to match the new design system while keeping the old HTML structure working.
- **Build System**: The Go build system embeds `static/css` via `embed.FS`. The build passes as long as the directory structure remains valid.

## Icon System Implementation
- Created a comprehensive set of SVG icons for navigation, status, and interface types.
- Used a consistent 24x24 viewBox with `currentColor` for flexible styling via CSS.
- Stroke-based icons (1-3 paths) ensure clarity at small sizes (16-20px).
- Reused icon concepts for related entities (e.g., `wireguard` -> `iface-wireguard`) to maintain visual consistency.
- Verified that `go:embed` handles the new directory structure correctly.
- Discovered that `go:embed` wildcards like `static/*` may cause issues with empty subdirectories (e.g., `static/css`), requiring either a file inside or ignoring the error if `go build` passes.

## Sidebar Redesign Implementation
- **Capability-Based Rendering**: Used `DetectCapabilities` in Go handlers to pass a `Capabilities` struct to the template, allowing conditional rendering of sidebar sections (e.g., WiFi, VPN) only when the hardware/software supports it.
- **CSS Masking for Icons**: Leveraged `mask-image` with `currentColor` background for sidebar icons. This allows the icon color to automatically match the text color (including hover/active states) without needing separate SVG files for each state.
- **Active State Handling**: Passed `ActivePage` string from each handler to the template. The sidebar template uses `{{if eq .ActivePage "page"}}active{{end}}` to apply the active class.
- **Grouped Navigation**: Structured the sidebar into logical groups (NETWORK, WIRELESS, VPN, SERVICES, SYSTEM) with small, uppercase headers for better scanability.

## [2026-02-20] Task: T13 Dashboard Refresh
- Redesigned dashboard using card-header and health-bar components
- Updated dashboard.go to calculate MemClass/CPUClass for health bars
- Used .data-table for disk usage
- Preserved all data bindings while changing structure

## [2026-02-20] Task: T14 Responsive Layout
- Implemented responsive sidebar:
  - Mobile (≤768px): Hidden by default, toggles with hamburger, overlay click closes it.
  - Tablet (769px–1024px): Icon-only mode, text hidden.
  - Desktop (>1024px): Full sidebar (unchanged).
- Added hamburger button to 'base.html' topbar.
- Added sidebar toggle logic to 'app.js' (click, overlay, htmx navigation).
- Verified 'go build ./...' passes.
