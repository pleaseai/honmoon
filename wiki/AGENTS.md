# AGENTS.md — Honmoon Wiki

This folder is the generated **VitePress** documentation site for Honmoon. It is built from
source-grounded Markdown with dark-mode Mermaid diagrams and click-to-zoom.

## Build & Run Commands

```bash
cd wiki
bun install            # install VitePress + mermaid + medium-zoom
bun run dev            # local dev server with HMR
bun run build          # production build → .vitepress/dist
bun run preview        # preview the built site

# Regenerate the LLM full-content file after editing pages
bun .vitepress/gen-llms-full.mjs
```

The build must complete cleanly. Mermaid syntax errors, `<br/>` in Mermaid labels, and bare
generics (`Vec<T>`, `Task<string>`) outside code fences will break the Vue compiler.

## Structure

| Path | What |
|------|------|
| `index.md` | Developer-focused landing page (no marketing hero). |
| `getting-started/` | Overview, installation, quick start, policy authoring. |
| `deep-dive/` | Architecture, policy engine, protocol parsing, gateway, control plane, roadmap. |
| `onboarding/` | Contributor, Staff Engineer, Executive, Product Manager guides. |
| `.vitepress/config.mts` | Site config, sidebar, dark Mermaid theme variables. |
| `.vitepress/theme/` | Daytona-inspired dark theme, custom CSS, diagram zoom overlay. |
| `llms.txt`, `llms-full.txt` | LLM-friendly summaries (full content inlined in the latter). |

## Content Conventions

- **Citations**: link to source as `[path:line](https://github.com/pleaseai/honmoon/blob/master/path#Lline)`.
  Every architectural claim needs a source. Each Mermaid diagram is followed by a
  `<!-- Sources: … -->` comment.
- **Mermaid**: dark-mode node fills `#2d333b`, borders `#6d5dfc`, text `#e6edf3`; subgraph
  backgrounds `#161b22`. Use `<br>` not `<br/>`. Use `autonumber` in every `sequenceDiagram`.
- **Frontmatter**: every page has `title` and `description`.
- **Honesty**: mark implemented vs planned/scaffold explicitly (`<span class="status-done">` /
  `status-planned` / `status-caveat`). This is a security tool — never overstate.
- **Cross-links**: relative links between wiki pages; a "Related Pages" + "References" section
  ends each page.

## Boundaries

- ✅ **Always**: run `bun run build` after edits; keep citations accurate to real file/line;
  regenerate `llms-full.txt` after content changes.
- ⚠️ **Ask first**: modifying `.vitepress/theme/` (test the build after); restructuring the
  sidebar in `config.mts`.
- 🚫 **Never**: delete generated pages wholesale; introduce `<br/>` or unescaped `<…>` generics
  in Markdown prose; present a planned/stub feature as working.
