#!/bin/sh
# Lists one filesystem image as its reference tool extracts it, one line per file, link and directory:
#   <type f|l|d> <mode, octal> <size> <sha-256 or -> <path>[ -> <link target>]
# Usage (as root, so modes and owners are kept): sh reference.sh <format> <image>
# Each format's reference tool and its native options are in the table below; a tool may be replaced by setting its variable.
set -eu
format=$1 image=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out="$work/out"
mkdir -p "$out"
case "$format" in
    squashfs) ${SQUASHFS_EXTRACTOR:-unsquashfs} -n -no-xattrs -f -d "$out" "$image" >/dev/null ;;
    ubi) ${UBI_EXTRACTOR:-ubireader_extract_images} -o "$work/ubi" "$image" >/dev/null
        # one file per volume, named as the volume table names it
        for f in "$work"/ubi/*/*; do v=${f##*_vol-}; mv "$f" "$out/${v%.ubifs}"; done ;;
    ubifs) ${UBIFS_EXTRACTOR:-ubireader_extract_files} -k -o "$out" "$image" >/dev/null ;;
    jffs2) ${JFFS2_EXTRACTOR:-jefferson} -f -d "$out" "$image" >/dev/null ;;
    ext) ${EXT_EXTRACTOR:-debugfs} -R "rdump / $out" "$image" >/dev/null 2>&1 ;;
    fat) ${FAT_EXTRACTOR:-mcopy} -s -n -i "$image" ::/ "$out" ;;
    cramfs) rmdir "$out"; ${CRAMFS_EXTRACTOR:-fsck.cramfs} -x "$out" "$image" >/dev/null ;;
    cpio) (cd "$out" && ${CPIO_EXTRACTOR:-cpio} -idm --quiet --no-absolute-filenames < "$image") ;;
    # libfdt's fdtget rather than dumpimage, which refuses node names with a unit address (kernel@0)
    fit) get=${FIT_EXTRACTOR:-fdtget}
        total=$(od -An -tu4 --endian=big -j4 -N4 "$image" | tr -d " ")
        for name in $($get -l "$image" /images); do
            node=/images/$name
            if size=$($get -t u "$image" "$node" data-size 2>/dev/null); then
                at=$($get -t u "$image" "$node" data-position 2>/dev/null) || at=$(( (total + 3) / 4 * 4 + $($get -t u "$image" "$node" data-offset) ))
                tail -c +$((at + 1)) "$image" | head -c "$size" > "$work/part"
            else $get -t bx "$image" "$node" data | awk '{ for (i = 1; i <= NF; i++) printf "%02s", $i }' | tr " " 0 | xxd -r -p > "$work/part"
            fi
            case "$($get "$image" "$node" compression 2>/dev/null)" in
                gzip) gzip -dc < "$work/part" > "$out/$name" || [ $? -eq 2 ] ;; # 2: a warning (padding after the stream)
                lzma) xz -dc --format=lzma < "$work/part" > "$out/$name" ;;
                *) mv "$work/part" "$out/$name" ;;
            esac
        done ;;
    *) echo "unknown format $format" >&2; exit 2 ;;
esac
cd "$out"
find . -type f -print0 | xargs -0 -r sha256sum | sed 's|  \./|\t|' > "$work/sums"
find . -mindepth 1 \( -type f -o -type l -o -type d \) -printf '%y\t%m\t%s\t%P\t%l\n' | LC_ALL=C sort -t "$(printf '\t')" -k4 |
    awk -F '\t' -v sums="$work/sums" 'BEGIN { while ((getline l < sums) > 0) { i = index(l, "\t"); sha[substr(l, i + 1)] = substr(l, 1, i - 1) } }
        $1 == "l" { print "l", $2, $3, "-", $4 " -> " $5; next }
        $1 == "d" { print "d", $2, 0, "-", $4; next }
        { print "f", $2, $3, sha[$4], $4 }'
