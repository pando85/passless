#!/usr/bin/env python3
"""Apply import grouping and sorting rules to Rust files.

This script implements the rules described in `copilot-instructions.md`.

Usage:
  ./tools/apply_import_rules.py [--dry-run] [path...]

If no paths are provided, the script walks the repository and processes all `.rs` files.
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple


USE_RE = re.compile(r'^(?P<indent>\s*)(?P<pub>pub\s+)?use\s+(?P<rest>.+?);\s*$')


def parse_use(rest: str) -> Tuple[str, List[str]]:
    """Return (base_path, items).

    Examples:
      'crate::pin_token::{Permission, PinToken}' -> ('crate::pin_token', ['Permission','PinToken'])
      'std::sync::Arc' -> ('std::sync', ['Arc'])
      'serde::Serialize' -> ('serde', ['Serialize'])
    """
    # Remove outer parens/spaces
    rest = rest.strip()
    # If there is a brace group
    if '{' in rest:
        m = re.match(r'(?P<base>[^\{]+)::\{(?P<inner>.*)\}\s*$', rest)
        if m:
            base = m.group('base').strip()
            inner = m.group('inner')
            # split by commas, strip
            items = [x.strip() for x in inner.split(',') if x.strip()]
            return base, items
    # No braces: split by :: into path and last ident
    parts = rest.split('::')
    if len(parts) == 1:
        return parts[0], [parts[0]]
    base = '::'.join(parts[:-1])
    item = parts[-1]
    return base, [item]


def group_key(base: str) -> int:
    if base.startswith('super'):
        return 0
    if base.startswith('self'):
        return 1
    if base.startswith('crate'):
        return 2
    # special ordering: put passless_core after crate but before std
    if base.startswith('passless_core'):
        return 2.5
    # place soft_fido2 after passless_core but before std
    if base.startswith('soft_fido2'):
        return 2.6
    if base.startswith('std'):
        return 3
    return 4


def normalize_use_lines(lines: List[str]) -> List[str]:
    # collect uses with their pub flag and indent
    groups = defaultdict(lambda: defaultdict(set))  # pub->base->set(items)
    order = defaultdict(list)  # track original order of bases per pub

    other_lines = []
    leading_ws = ''

    for i, line in enumerate(lines):
        m = USE_RE.match(line)
        if not m:
            other_lines.append(line)
            continue
        pub = bool(m.group('pub'))
        rest = m.group('rest')
        base, items = parse_use(rest)
        groups[pub][base].update(items)
        if base not in order[pub]:
            order[pub].append(base)
        if i == 0:
            leading_ws = m.group('indent')

    # produce sorted output with blank lines between logical group categories
    out = []
    for pub in (True, False):
        # group bases by group_key
        bases_by_group = defaultdict(list)
        for base in groups[pub].keys():
            bases_by_group[group_key(base)].append(base)

        group_keys_sorted = sorted(bases_by_group.keys())
        first_group_emitted = False
        for gk in group_keys_sorted:
            bases = bases_by_group[gk]
            bases.sort()  # alphabetical within group
            # emit a separating blank line between different groups
            if first_group_emitted:
                out.append('')
            for base in bases:
                items = sorted(groups[pub][base])
                if len(items) == 1 and items[0] == base.split('::')[-1]:
                    line = f"{leading_ws}{'pub ' if pub else ''}use {base}::{items[0]};"
                else:
                    inner = ', '.join(items)
                    line = f"{leading_ws}{'pub ' if pub else ''}use {base}::{{{inner}}};"
                out.append(line)
            first_group_emitted = True
        # after finishing pub group, add blank line to separate pub and non-pub if both exist
        if group_keys_sorted:
            out.append('')
    # remove trailing blank
    if out and out[-1] == '':
        out.pop()

    # if there were other lines (non-use) we preserve their order after the block
    out.extend(other_lines)
    return out


def process_file(path: Path, dry_run: bool = False) -> bool:
    text = path.read_text(encoding='utf-8')
    lines = text.splitlines()

    i = 0
    changed = False
    new_lines = []
    while i < len(lines):
        # find a contiguous block of use/pub use lines (allowing blank lines between grouped logical blocks)
        if USE_RE.match(lines[i]):
            start = i
            block = []
            while i < len(lines) and (lines[i].strip() == '' or USE_RE.match(lines[i])):
                # allow blank lines inside block; capture as-is
                block.append(lines[i])
                i += 1
            normalized = normalize_use_lines(block)
            # compare
            if normalized != block:
                changed = True
            new_lines.extend(normalized)
        else:
            new_lines.append(lines[i])
            i += 1

    if changed:
        new_text = '\n'.join(new_lines) + '\n'
        if dry_run:
            print(f"[DRY-RUN] Would update: {path}")
        else:
            path.write_text(new_text, encoding='utf-8')
            print(f"Updated: {path}")
    return changed


def iter_rs_files(paths: List[Path]) -> List[Path]:
    files = []
    if not paths:
        root = Path('.').resolve()
        for p in root.rglob('*.rs'):
            # skip target and vendor directories
            if any(part in ('target', 'vendor') for part in p.parts):
                continue
            files.append(p)
    else:
        for p in paths:
            p = Path(p)
            if p.is_dir():
                for f in p.rglob('*.rs'):
                    if any(part in ('target', 'vendor') for part in f.parts):
                        continue
                    files.append(f)
            elif p.is_file() and p.suffix == '.rs':
                files.append(p)
    return files


def main(argv: List[str]):
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='*', help='Files or directories to process')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)

    files = iter_rs_files([Path(p) for p in args.paths])
    if not files:
        print('No Rust files found')
        return 0

    modified = []
    for f in files:
        try:
            if process_file(f, dry_run=args.dry_run):
                modified.append(str(f))
        except Exception as e:
            print(f"Error processing {f}: {e}", file=sys.stderr)

    print(f"Processed {len(files)} files, modified {len(modified)} files")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
