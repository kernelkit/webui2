# CSS Redesign Learnings

- **Two-Layer Token System**: Successfully implemented a primitive/semantic token system. Primitives (slate-50, blue-500) are defined in `:root`, and semantics (bg, fg, primary) map to them. This makes dark mode implementation trivial by remapping semantics in `@media (prefers-color-scheme: dark)`.
- **Sidebar Persistence**: The sidebar needed to stay dark regardless of the theme. This was achieved by defining specific `--sidebar-*` variables that map to dark primitives (slate-800) in the default `:root` and do *not* change in the dark media query.
- **Component Preservation**: Legacy components like `.info-card h2` needed specific overrides to match the new design system while keeping the old HTML structure working.
- **Build System**: The Go build system embeds `static/css` via `embed.FS`. The build passes as long as the directory structure remains valid.
