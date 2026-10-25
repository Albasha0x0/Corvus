#!/bin/sh
# Builds the AppImage and snap fixtures from the trees below, with fixed times and root ownership:
#   ledger-gzip.AppImage, ledger-zstd.AppImage  an ELF runtime stub (stub.py) followed by a squashfs of Ledger.AppDir
#   ledger_1.2.0_amd64.snap                     snap pack of the ledger snap tree
# Usage, from this folder: sh build.sh (needs mksquashfs, snap and python3).
set -eu
here=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH=1767225600

app="$work/Ledger.AppDir"
mkdir -p "$app/usr/bin" "$app/usr/share/ledger"
printf '#!/bin/sh\nexec "$(dirname "$0")/usr/bin/ledger" "$@"\n' > "$app/AppRun"
printf '#!/bin/sh\necho ledger 1.2.0\n' > "$app/usr/bin/ledger"
printf 'Shipping notes for the ledger sample.\n' > "$app/usr/share/ledger/notes.txt"
printf '[Desktop Entry]\nType=Application\nName=Ledger\nExec=ledger\nIcon=ledger\nCategories=Office;\nX-AppImage-Version=1.2.0\n' > "$app/ledger.desktop"
printf 'ledger icon placeholder\n' > "$app/ledger.png"
ln -s ledger.png "$app/.DirIcon"
chmod 755 "$app/AppRun" "$app/usr/bin/ledger"
for comp in gzip zstd; do
    mksquashfs "$app" "$work/$comp.squashfs" -root-owned -noappend -no-xattrs -no-progress -quiet -comp $comp
    python3 "$here/stub.py" "$work/$comp.squashfs" "$here/ledger-$comp.AppImage"
done

snap="$work/snap"
mkdir -p "$snap/meta" "$snap/bin"
printf '#!/bin/sh\necho ledger 1.2.0\n' > "$snap/bin/ledger"
chmod 755 "$snap/bin/ledger"
cat > "$snap/meta/snap.yaml" <<'EOF'
name: ledger
version: '1.2.0'
summary: Ledger sample package
description: |
  A sample application that prints its version.
architectures:
  - amd64
base: core22
grade: stable
confinement: strict
apps:
  ledger:
    command: bin/ledger
  ledger-report:
    command: bin/ledger
    plugs: [home]
EOF
find "$snap" -exec touch -h -d @$SOURCE_DATE_EPOCH {} +
snap pack "$snap" "$work" > /dev/null
cp "$work/ledger_1.2.0_amd64.snap" "$here/"
