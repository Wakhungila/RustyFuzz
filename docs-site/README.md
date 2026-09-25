# Documentation site

Content is derived from the current CLI and workspace implementation. The site uses Just the Docs for search and responsive navigation, with local layout, style, and navigation overrides.

```bash
cd docs-site
bundle install
bundle exec jekyll build
python3 -m http.server 4000 --bind 127.0.0.1 --directory _site
```

Publish only `_site`. The existing GitHub Pages workflow builds this directory from source.

Content changes should be checked against `src/cli/commands.rs`, lifecycle/input types, and the current artifact/operations implementation. Older design documents contain target architecture as well as implemented behavior.

Run the structural checker after building:

```bash
python3 scripts/check_site.py _site
```
