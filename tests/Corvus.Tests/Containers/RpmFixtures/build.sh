#!/bin/sh
# Rebuilds the rpm fixtures from ledger-tools.spec with rpmbuild (rpm 4.17): the binary package with gzip, bzip2, xz
# and zstd payloads, and the source package. Run on Linux or in WSL (wsl.exe -e sh build.sh) from this folder.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top/SPECS"
cp "$here/ledger-tools.spec" "$top/SPECS/"
export SOURCE_DATE_EPOCH=1767225600
# A fixed build host and time keep the build machine out of the headers.
build() {
    rpmbuild --define "_topdir $top" --define "_buildhost fixture.build" --define "use_source_date_epoch_as_buildtime 1" \
        --define "clamp_mtime_to_source_date_epoch 1" \
        --quiet "$@" "$top/SPECS/ledger-tools.spec"
}
for c in gzip:w9.gzdio bzip2:w9.bzdio xz:w6.xzdio zstd:w19.zstdio; do
    build --define "_binary_payload ${c#*:}" -bb
    mv "$top/RPMS/noarch/ledger-tools-1.2.0-3.noarch.rpm" "$here/ledger-tools-${c%%:*}.rpm"
done
build -bs
mv "$top/SRPMS/ledger-tools-1.2.0-3.src.rpm" "$here/ledger-tools.src.rpm"
