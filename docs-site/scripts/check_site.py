#!/usr/bin/env python3
"""Check generated documentation links, anchors, assets, and publication scope."""
import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.refs, self.ids, self.h1 = [], set(), 0
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if tag == 'h1':
            self.h1 += 1
        for key in ('href', 'src'):
            if key in attrs:
                self.refs.append(attrs[key])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', type=Path)
    parser.add_argument('--baseurl', default='')
    args = parser.parse_args()
    root = args.site.resolve()
    pages = {p: Page(p.read_text()) for p in root.rglob('*.html')}
    errors = []
    prefix = args.baseurl.rstrip('/')
    for path, page in pages.items():
        name = path.relative_to(root).as_posix()
        if page.h1 != 1:
            errors.append(f'{name}: expected one h1, got {page.h1}')
        for ref in page.refs:
            url = urlsplit(urljoin('https://docs.invalid' + prefix + '/' + name, ref))
            if url.netloc != 'docs.invalid' or url.scheme not in ('http', 'https'):
                continue
            route = unquote(url.path)
            if prefix and not route.startswith(prefix + '/'):
                errors.append(f'{name}: URL escapes baseurl: {ref}')
                continue
            route = route[len(prefix):].lstrip('/')
            target = root / route
            if target.is_dir():
                target /= 'index.html'
            if not target.is_file():
                errors.append(f'{name}: missing {ref}')
            elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
                errors.append(f'{name}: missing anchor {ref}')
        text = path.read_text()
        if 'https://github.com/Wakhungila/RustyFuzz' not in text:
            errors.append(f'{name}: missing repository link')
        if 'favicon.ico' not in text:
            errors.append(f'{name}: missing favicon')
    for path in root.rglob('*'):
        if path.is_symlink() or path.name in {'.env', 'config.toml', 'Cargo.toml', '.git'} or path.suffix == '.rs':
            errors.append(f'unexpected published file: {path.relative_to(root)}')
    search = root / 'assets/js/search-data.json'
    if search.exists():
        index = json.loads(search.read_text())
        indexed = {urlsplit(item['url']).path for item in index.values()}
        expected = {prefix + '/' + p.relative_to(root).as_posix() for p in pages}
        expected = {u[:-10] if u.endswith('index.html') else u for u in expected}
        if indexed != expected:
            errors.append(f'search coverage mismatch: {indexed ^ expected}')
    else:
        errors.append('missing search index')
    if not pages:
        errors.append('no generated pages')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'PASS: {len(pages)} pages; links, anchors, assets, search index, and publication scope ({prefix or "/"}).')

if __name__ == '__main__':
    main()
