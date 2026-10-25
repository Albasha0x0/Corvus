#!/bin/sh
# Prints what unsquashfs reads from an AppImage or snap, one tab-separated record per line:
#   O <squashfs offset>
#   L <path> <mode in octal> <size> (regular files)
#   S <path> <link target>
#   C <path> <SHA-256>
# Usage: sh reference.sh <file> (needs unsquashfs and readelf).
set -eu
file=$1
offset=0
if [ "$(head -c 4 "$file" | od -An -c | tr -d ' ')" = "177ELF" ]; then
    # The squashfs image follows the runtime's section headers.
    set -- $(readelf -h "$file" | awk -F: '/Start of section headers/ {o=$2+0} /Size of section headers/ {s=$2+0} /Number of section headers/ {n=$2+0} END {print o, s, n}')
    offset=$(($1 + $2 * $3))
fi
printf 'O\t%s\n' "$offset"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
unsquashfs -o "$offset" -n -d "$dir/root" "$file" > /dev/null
cd "$dir/root"
find . -mindepth 1 | sort | while read -r f; do
    p=${f#./}
    if [ -L "$f" ]; then printf 'S\t%s\t%s\n' "$p" "$(readlink "$f")"
    elif [ -f "$f" ]; then
        printf 'L\t%s\t%s\t%s\n' "$p" "$(stat -c %a "$f")" "$(stat -c %s "$f")"
        printf 'C\t%s\t%s\n' "$p" "$(sha256sum "$f" | cut -d' ' -f1)"
    fi
done
