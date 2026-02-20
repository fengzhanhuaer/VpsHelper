#!/usr/bin/env sh
set -eu

usage() {
    cat <<'EOF'
Usage: scripts/check_text_integrity.sh [--all|--staged]

  --all      Check tracked files from working tree (default)
  --staged   Check staged content in git index (for pre-commit)
EOF
}

mode="${1:---all}"
case "$mode" in
    --all|--staged) ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# Only check text-oriented sources/templates/docs.
set -- \
    '*.go' '*.html' '*.md' '*.txt' '*.json' '*.yaml' '*.yml' '*.toml' \
    '*.css' '*.js' '*.ts' '*.tsx' '*.jsx' '*.sh' '*.bat' '*.ps1'
exclude_self=':(exclude)scripts/check_text_integrity.sh'

# Typical mojibake fragments seen when UTF-8/GBK are decoded incorrectly.
mojibake_pattern='�|锛|銆|鈥|锟|杩斿洖|閫€鍑|鏆傛棤|璇锋眰|鍒锋柊|鎿嶄綔|浼氳瘽|闃茬伀澧|鍙戦€|鑷姩|鍛戒护'
# Broken closing HTML tags, e.g. "?/p>" (where "<" became "?").
broken_tag_pattern='\?/[A-Za-z][A-Za-z0-9:-]*>'

status=0
if [ "$mode" = "--staged" ]; then
    mojibake_hits="$(git grep --cached -nI -E "$mojibake_pattern" -- "$@" "$exclude_self" || true)"
    tag_hits="$(git grep --cached -nI -E "$broken_tag_pattern" -- "$@" "$exclude_self" || true)"
else
    mojibake_hits="$(git grep -nI -E "$mojibake_pattern" -- "$@" "$exclude_self" || true)"
    tag_hits="$(git grep -nI -E "$broken_tag_pattern" -- "$@" "$exclude_self" || true)"
fi

if [ -n "$mojibake_hits" ]; then
    echo "[FAIL] Possible mojibake detected:" >&2
    echo "$mojibake_hits" >&2
    status=1
fi

if [ -n "$tag_hits" ]; then
    echo "[FAIL] Broken closing tags detected (expected </tag>):" >&2
    echo "$tag_hits" >&2
    status=1
fi

if [ "$status" -ne 0 ]; then
    echo "Text integrity check failed. Please fix encoding/corrupted tags before commit." >&2
    exit "$status"
fi

echo "Text integrity check passed."
