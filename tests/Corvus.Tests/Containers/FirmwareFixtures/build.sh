#!/bin/sh
# Rebuilds the firmware filesystem fixtures from one small root tree with the Linux tools that write each format:
# mksquashfs (squashfs-tools 4.5: gzip, lzma, lzo, lz4, xz, zstd), mkfs.cramfs (both byte orders), mke2fs -d (ext2, ext4),
# mkfs.fat with a loop mount (FAT12, FAT16, FAT32; needs root) and cpio (newc, odc, bin). Each image is stored gzipped;
# <image>.list is the reference file list: unsquashfs -lls for squashfs, the tree's own list (path, size) for the others.
# Run from a Linux shell (WSL works): sh build.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
isa="$here/../../Engines/IsaFixtures"
tmp=$(mktemp -d)
trap 'umount "$tmp/mnt" 2>/dev/null || true; rm -rf "$tmp"' EXIT
root="$tmp/root"
mkdir -p "$root/bin" "$root/lib" "$root/etc/config" "$root/www" "$root/sbin" "$root/usr/share/doc/deep/er"
cp "$isa/mips32be.elf" "$root/bin/busybox"
cp "$isa/armbe.elf" "$root/lib/libuci.so"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root/etc/passwd"
: > "$root/etc/empty"
i=0
while [ $i -lt 6000 ]; do printf 'option entry_%05d value_%05d\n' $i $((i * 7 % 9973)); i=$((i + 1)); done > "$root/etc/config/large.conf"
printf '<html><body>router</body></html>\n' > "$root/www/index.html"
printf 'deep file\n' > "$root/usr/share/doc/deep/er/notes.txt"
ln -s ../bin/busybox "$root/sbin/init"
find "$root" -exec touch -h -d '2026-01-01 00:00:00' {} +

list() { (cd "$root" && find . -type f | sed 's|^\./||' | sort | while read -r f; do printf '%s %s\n' "$f" "$(stat -c %s "$f")"; done); }

for c in gzip lzma lzo lz4 xz zstd; do
    out="$tmp/squashfs-$c.img"
    mksquashfs "$root" "$out" -comp "$c" -noappend -all-root -quiet -b 65536 >/dev/null
    unsquashfs -lls "$out" | grep '^[-dlcbps][-rwxsStT]\{9\} ' > "$here/squashfs-$c.img.list"
    gzip -9n < "$out" > "$here/squashfs-$c.img.gz"
done

mkfs.cramfs "$root" "$tmp/cramfs-le.img" >/dev/null
mkfs.cramfs -N big "$root" "$tmp/cramfs-be.img" >/dev/null
for e in le be; do gzip -9n < "$tmp/cramfs-$e.img" > "$here/cramfs-$e.img.gz"; done

for t in ext2 ext4; do
    mke2fs -q -t "$t" -b 1024 -d "$root" -E root_owner=0:0 -U 00000000-0000-0000-0000-000000000001 "$tmp/$t.img" 2048
    gzip -9n < "$tmp/$t.img" > "$here/$t.img.gz"
done

mkdir -p "$tmp/mnt"
for f in 12:2048 16:16384 32:34000; do
    bits=${f%%:*}; kb=${f##*:}
    mkfs.fat -F "$bits" -i 12345678 -n FIRMWARE -C "$tmp/fat$bits.img" "$kb" >/dev/null 2>&1
    mount -o loop "$tmp/fat$bits.img" "$tmp/mnt"
    (cd "$root" && find . -type d | while read -r d; do mkdir -p "$tmp/mnt/$d"; done; find . -type f | while read -r f; do cp "$f" "$tmp/mnt/$f"; done)
    cp "$root/etc/passwd" "$tmp/mnt/Long File Name.txt"
    umount "$tmp/mnt"
    gzip -9n < "$tmp/fat$bits.img" > "$here/fat$bits.img.gz"
done

for h in newc odc bin; do
    (cd "$root" && find . | sort | cpio -o -H "$h" --quiet) > "$tmp/$h.cpio"
    gzip -9n < "$tmp/$h.cpio" > "$here/cpio-$h.cpio.gz"
done

list > "$here/tree.list"
ls -l "$here"
