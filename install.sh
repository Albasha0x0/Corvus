#!/bin/sh
# Installs NetDecompilerMcp for the current user and registers it with every installed MCP client.
#   curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
# Uninstall:
#   curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh -s -- --uninstall
# Environment: NDM_REPO (owner/name), NDM_HOME (install folder), NDM_ARCHIVE (local release archive),
# GITHUB_TOKEN (private repositories).
set -eu

REPO="${NDM_REPO:-Albasha0x0/Corvus}"
ROOT="${NDM_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/net-decompiler-mcp}"
BIN="$HOME/.local/bin"
EXE="$ROOT/current/NetDecompilerMcp"

fail() { echo "error: $*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    if [ -x "$EXE" ]; then "$EXE" uninstall; else echo "NetDecompilerMcp is not installed."; fi
    exit 0
fi

case "$(uname -s)" in
    Linux)
        os=linux
        if [ -f /etc/alpine-release ] || (ldd --version 2>&1 | grep -qi musl); then os=linux-musl; fi ;;
    Darwin) os=osx ;;
    *) fail "unsupported system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail "unsupported processor $(uname -m)" ;;
esac
asset="NetDecompilerMcp-$os-$arch.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
archive="$tmp/$asset"

if [ -n "${NDM_ARCHIVE:-}" ]; then
    cp "$NDM_ARCHIVE" "$archive"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
    auth="Authorization: Bearer $GITHUB_TOKEN"
    url=$(curl -fsSL -H "$auth" "https://api.github.com/repos/$REPO/releases/latest" | tr -d '\r\n' | tr '{' '\n' \
        | grep "\"name\": *\"$asset\"" | sed -n 's/.*"url": *"\([^"]*\/releases\/assets\/[0-9]*\)".*/\1/p' | head -n 1)
    [ -n "$url" ] || fail "the latest release of $REPO has no $asset"
    curl -fsSL -H "$auth" -H "Accept: application/octet-stream" "$url" -o "$archive"
else
    echo "Downloading $asset..."
    url="https://github.com/$REPO/releases/latest/download/$asset"
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$archive"
    elif command -v wget >/dev/null 2>&1; then wget -q "$url" -O "$archive"
    else fail "curl or wget is required"; fi
fi

mkdir -p "$ROOT/versions"
staging="$ROOT/versions/.new-$$"
rm -rf "$staging"
mkdir -p "$staging"
tar -xzf "$archive" -C "$staging"
chmod +x "$staging/NetDecompilerMcp"
if ! version=$("$staging/NetDecompilerMcp" version); then
    rm -rf "$staging"
    if [ "$os" = linux-musl ]; then fail "the build needs the C++ runtime: apk add libstdc++ libgcc, then run this again"; fi
    fail "the downloaded build does not run on this machine"
fi

target="$ROOT/versions/$version"
rm -rf "$target"
mv "$staging" "$target"
ln -sfn "$target" "$ROOT/current"
for dir in "$ROOT"/versions/*; do
    [ "$dir" = "$target" ] || rm -rf "$dir"
done

mkdir -p "$BIN"
ln -sf "$EXE" "$BIN/NetDecompilerMcp"

echo "Installed NetDecompilerMcp $version to $target"
"$EXE" install
echo
echo "Done. Commands: NetDecompilerMcp status | update | uninstall"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "Add $BIN to PATH to run NetDecompilerMcp from a terminal (the MCP clients do not need it)." ;;
esac
