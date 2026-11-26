#!/usr/bin/env bash
# Usage: scripts/import-stalwart-rules.sh <checkout of github.com/stalwartlabs/spam-filter>
set -euo pipefail

src="${1:?path to a checkout of stalwartlabs/spam-filter}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$root/data/stalwart"
commit="$(git -C "$src" rev-parse HEAD)"

rm -rf "$dest"
mkdir -p "$dest/rules" "$dest/lists"
cp "$src/LICENSE-MIT" "$dest/LICENSE-MIT"
cp "$src"/lists/*.txt "$dest/lists/"

fold() {
  python3 -c '
import sys
raw = sys.stdin.read()
out, i, n = [], 0, len(raw)
while i < n:
    c = raw[i]
    if raw.startswith("\"\"\"", i):
        end = raw.index("\"\"\"", i + 3) + 3
        out.append(raw[i:end]); i = end
    elif c == "\"":
        out.append(c); i += 1
        while i < n:
            c = raw[i]
            if c == "\\":
                out.append(raw[i:i + 2]); i += 2
            elif c == "\"":
                out.append(c); i += 1; break
            elif c == "\n":
                out.append(" "); i += 1
            else:
                out.append(c); i += 1
    elif c == "#":
        end = raw.find("\n", i)
        end = n if end < 0 else end
        out.append(raw[i:end]); i = end
    else:
        out.append(c); i += 1
sys.stdout.write("".join(out))
'
}

for file in "$src"/rules/*.toml "$src"/lists/*.toml; do
  case "$file" in
    */rules/*) target="$dest/rules/$(basename "$file")" ;;
    *) target="$dest/lists/$(basename "$file")" ;;
  esac
  fold < "$file" > "$target"
done

cat > "$dest/SOURCE.md" <<MD
# Source

Imported unchanged, except that line breaks inside quoted strings are folded into spaces so the
files are valid TOML, from [stalwartlabs/spam-filter](https://github.com/stalwartlabs/spam-filter)
at commit \`$commit\`.

Copyright (C) 2024 Stalwart Labs LLC. Used under the MIT license (the project is dual licensed
MIT OR Apache-2.0); see [LICENSE-MIT](LICENSE-MIT).

Update with \`scripts/import-stalwart-rules.sh <checkout>\`.
MD
echo "imported $commit into $dest"
