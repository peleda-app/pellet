#!/usr/bin/env bash
# Downloads the evaluation corpora once into a cache outside the repository and runs pellet-eval.
#   PELLET_EVAL_DIR    cache directory (default ~/.cache/pellet-eval)
#   PELLET_EVAL_MONTH  month of the untroubled.org spam archive (default 2026-10)
# Extra arguments go to pellet-eval.
set -euo pipefail

dir="${PELLET_EVAL_DIR:-$HOME/.cache/pellet-eval}"
month="${PELLET_EVAL_MONTH:-2026-10}"
mkdir -p "$dir/archives"

fetch() {
  local url="$1" file="$dir/archives/${1##*/}"
  [ -s "$file" ] || curl -fsS -o "$file" "$url"
  echo "$file"
}

extract() {
  local archive="$1" into="$2"
  [ -d "$into" ] && return
  mkdir -p "$into.tmp"
  if command -v bsdtar >/dev/null; then
    bsdtar -xf "$archive" -C "$into.tmp"
  else
    7z x -y -o"$into.tmp" "$archive" >/dev/null
  fi
  mv "$into.tmp" "$into"
}

extract "$(fetch "https://www.untroubled.org/spam/$month.7z")" "$dir/untroubled/$month"
for set in easy_ham hard_ham spam; do
  extract "$(fetch "https://spamassassin.apache.org/old/publiccorpus/20030228_$set.tar.bz2")" "$dir/spamassassin/$set"
done

exec cargo run --release -q -p pellet-eval -- \
  --spam "$dir/untroubled/$month" \
  --spam "$dir/spamassassin/spam" \
  --ham "$dir/spamassassin/easy_ham" \
  --ham "$dir/spamassassin/hard_ham" \
  "$@"
