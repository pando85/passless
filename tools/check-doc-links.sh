#!/bin/sh
# Check internal markdown links in docs/ and README.md.
# Exits non-zero if any relative link target does not exist.
# Usage: tools/check-doc-links.sh

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPFILE="$(mktemp)"
trap 'rm -f "$TMPFILE"' EXIT

check_file() {
    file="$1"
    dir="$(dirname "$file")"

    grep -oE '\[([^]]*)\]\(([^)]*)\)' "$file" 2>/dev/null | while IFS= read -r match; do
        target="$(echo "$match" | sed 's/.*](\(.*\))/\1/')"

        case "$target" in
            http://*|https://*|mailto:*) continue ;;
            \#*) continue ;;
        esac

        target="${target%%#*}"
        [ -z "$target" ] && continue

        resolved="$dir/$target"
        if [ ! -e "$resolved" ]; then
            echo "BROKEN: $file -> $target" >> "$TMPFILE"
        fi
    done
}

find "$ROOT/docs" "$ROOT/README.md" -name '*.md' 2>/dev/null | while IFS= read -r f; do
    check_file "$f"
done

if [ -s "$TMPFILE" ]; then
    cat "$TMPFILE"
    exit 1
fi
