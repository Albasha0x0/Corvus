#!/bin/sh
# Rebuilds the virtual disk fixtures on Linux (as root, for the loop mount): ntfs-3g, qemu-img, parted, mkfs.vfat, mtools, attr.
#   sh build-disks.sh
# disk-gpt.vhdx.gz: a 24 MiB GPT disk whose partitions hold an NTFS volume (a text file, a nested folder, a zip package,
#   a compressed file and a Zone.Identifier stream) and a FAT16 volume; disk-mbr.vhd.gz (fixed) and
#   disk-mbr-dynamic.vhd.gz: the same layout under an MBR with the first partition left empty.
set -e
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cd "$work"

mkdir tree tree/docs "tree/docs/a folder with a long name"
printf 'hello from the volume' > tree/readme.txt
printf 'nested file' > "tree/docs/a folder with a long name/Quarterly Report (final).txt"
(cd tree && printf 'zipped' > inner.txt && python3 -c "import zipfile; z=zipfile.ZipFile('docs/setup.zip','w'); z.write('inner.txt'); z.close()" && rm inner.txt)
head -c 20000 /dev/zero | tr '\0' 'A' > repeated.txt

truncate -s 8M ntfs.img
mkntfs -F -Q -q -L CORVUS ntfs.img
mkdir mnt
mount -t ntfs-3g -o loop,streams_interface=windows ntfs.img mnt
cp -r tree/. mnt/
mkdir mnt/packed
setfattr -h -v 0x00000800 -n system.ntfs_attrib_be mnt/packed
cp repeated.txt mnt/packed/repeated.txt
printf '[ZoneTransfer]\r\nZoneId=3\r\n' > "mnt/docs/setup.zip:Zone.Identifier"
umount mnt

truncate -s 4M fat.img
mkfs.vfat -n FATVOL fat.img >/dev/null
mcopy -i fat.img tree/readme.txt ::/fat-readme.txt 2>/dev/null || true

for table in msdos gpt; do
  truncate -s 24M disk-$table.raw
  parted -s disk-$table.raw mklabel $table mkpart primary ntfs 2048s 18431s mkpart primary fat16 18432s 26623s
  [ $table = gpt ] && dd if=ntfs.img of=disk-$table.raw bs=512 seek=2048 conv=notrunc status=none
  dd if=fat.img of=disk-$table.raw bs=512 seek=18432 conv=notrunc status=none
done
qemu-img convert -f raw -O vpc -o subformat=fixed disk-msdos.raw disk-mbr.vhd
qemu-img convert -f raw -O vpc -o subformat=dynamic disk-msdos.raw disk-mbr-dynamic.vhd
qemu-img convert -f raw -O vhdx disk-gpt.raw disk-gpt.vhdx
for f in disk-mbr.vhd disk-mbr-dynamic.vhd disk-gpt.vhdx; do gzip -9 -n -c "$f" > "$here/$f.gz"; done
cd / && rm -rf "$work"
