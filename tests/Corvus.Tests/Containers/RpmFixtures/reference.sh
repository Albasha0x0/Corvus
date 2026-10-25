#!/bin/sh
# Prints what rpm reads from a package, one tab-separated record per line:
#   P <name>-<version>-<release>.<arch or src>
#   F <path> <size> <mode in octal> <user> <group> <link target> <digest> <flags>
#   X <scriptlet name> <SHA-256 of its body>
#   C <path> <SHA-256 of the payload file>
# Usage: sh reference.sh <package>
set -eu
pkg=$1
arch=$(rpm -qp --qf '%{ARCH}' "$pkg")
[ "$(rpm -qp --qf '%{SOURCERPM}' "$pkg")" = "(none)" ] && arch=src
rpm -qp --qf "P\t%{NAME}-%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}.$arch\n" "$pkg"
rpm -qp --qf '[F\t%{FILENAMES}\t%{FILESIZES}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILELINKTOS}\t%{FILEDIGESTS}\t%{FILEFLAGS}\n]' "$pkg"
for s in PREIN:preinstall POSTIN:postinstall PREUN:preuninstall POSTUN:postuninstall VERIFYSCRIPT:verify PRETRANS:pretrans POSTTRANS:posttrans; do
    body=$(rpm -qp --qf "%{${s%%:*}}" "$pkg")
    [ "$body" = "(none)" ] && continue
    printf 'X\t%s\t%s\n' "${s#*:}" "$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)"
done
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
rpm2cpio "$pkg" | (cd "$dir" && cpio -idm --quiet --no-absolute-filenames)
(cd "$dir" && find . -type f | sort | while read -r f; do printf 'C\t%s\t%s\n' "${f#./}" "$(sha256sum "$f" | cut -d' ' -f1)"; done)
