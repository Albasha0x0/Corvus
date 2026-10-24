#!/bin/sh
# Installs Corvus for the current user and registers it with the MCP clients it finds: existing
# registrations are refreshed, new clients are listed and registered after one confirmation (Enter = yes).
#   curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
# With options:
#   curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh -s -- --yes
# Uninstall (keeps your data; add --purge-data to delete it too):
#   curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh -s -- --uninstall
# Options: --version X installs that release (pinning or rolling back), --dry-run shows what would be installed and
# registered and changes nothing, --yes registers new clients without asking, --client a,b registers only those,
# --with-live installs the tested Frida into a private Python environment for the session tools and turns that on.
# The confirmation is read from the terminal (/dev/tty) even when the script itself arrives on stdin.
# Environment: CORVUS_VERSION (as --version), CORVUS_YES=1 (as --yes), CORVUS_REPO (owner/name), CORVUS_HOME (install folder),
# CORVUS_ARCHIVE (local release archive), CORVUS_SHA256SUMS (manifest to verify CORVUS_ARCHIVE against; without it a local
# archive is trusted as is), GITHUB_TOKEN (optional: a higher GitHub API rate limit), CORVUS_REQUIRE_ATTESTATION (1: refuse a
# build whose provenance was not checked; 0: skip the check, for a self-built archive).
# Downloads are verified against the release's SHA256SUMS; a missing manifest or a mismatch stops the install. With gh
# on PATH and signed in, the archive's build provenance must name this repository's release workflow.
set -eu

REPO="${CORVUS_REPO:-Albasha0x0/Corvus}"
ROOT="${CORVUS_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/Corvus}"
BIN="$HOME/.local/bin"
EXE="$ROOT/current/corvus"
# Migration only: the install made before the rename; the program's install command moves its registrations and data.
LEGACY_EXE="${XDG_DATA_HOME:-$HOME/.local/share}/net-decompiler-mcp/current/NetDecompilerMcp"

fail() { echo "error: $*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    shift
    if [ -x "$EXE" ]; then "$EXE" uninstall "$@"
    elif [ -x "$LEGACY_EXE" ]; then "$LEGACY_EXE" uninstall "$@"
    else echo "Corvus is not installed."; fi
    exit 0
fi

version="${CORVUS_VERSION:-}"
dry_run=""
# Options passed on to the program's install command.
setup_args=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || fail "--version needs a value"; version="$2"; shift ;;
        --version=*) version="${1#--version=}" ;;
        --dry-run) dry_run=1; setup_args="$setup_args --dry-run" ;;
        --yes|-y) setup_args="$setup_args --yes" ;;
        --with-live) setup_args="$setup_args --with-live" ;;
        --client) [ $# -ge 2 ] || fail "--client needs a value"; setup_args="$setup_args --client $2"; shift ;;
        --client=*) setup_args="$setup_args --client ${1#--client=}" ;;
        *) fail "unknown option $1 (options: --version X, --dry-run, --yes, --client a,b, --with-live, --uninstall)" ;;
    esac
    shift
done
version="${version#v}"
case "$version" in 0.*|1.[01]|1.[01].*) fail "release $version predates Corvus (1.2.0 is the first)" ;; esac
case "$setup_args" in *[!A-Za-z0-9_\ ,.-]*) fail "client names may use letters, digits, '-', '_', '.' and ','" ;; esac

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
asset="corvus-$os-$arch.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
archive="$tmp/$asset"

sums="$tmp/SHA256SUMS"
unverified="refusing to install an unverified build"
if [ -n "$version" ]; then release="v$version"; tag="v$version"; else release="the latest release"; tag=""; fi

if [ -n "${CORVUS_ARCHIVE:-}" ]; then
    cp "$CORVUS_ARCHIVE" "$archive"
    release="$CORVUS_ARCHIVE"
    if [ -n "${CORVUS_SHA256SUMS:-}" ]; then cp "$CORVUS_SHA256SUMS" "$sums"; source="$CORVUS_SHA256SUMS"; else sums=""; source="none (local archive)"; fi
elif [ -n "${GITHUB_TOKEN:-}" ]; then
    auth="Authorization: Bearer $GITHUB_TOKEN"
    if [ -n "$version" ]; then api="https://api.github.com/repos/$REPO/releases/tags/v$version"; else api="https://api.github.com/repos/$REPO/releases/latest"; fi
    curl -fsSL -H "$auth" "$api" | tr -d '\r\n' | tr '{' '\n' > "$tmp/release"
    tag=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/release" | head -n 1)
    asset_url() {
        grep "\"name\": *\"$1\"" "$tmp/release" | sed -n 's/.*"url": *"\([^"]*\/releases\/assets\/[0-9]*\)".*/\1/p' | head -n 1
    }
    url=$(asset_url "$asset")
    [ -n "$url" ] || fail "$release of $REPO has no $asset"
    sums_url=$(asset_url SHA256SUMS)
    [ -n "$sums_url" ] || fail "$release of $REPO has no SHA256SUMS manifest; $unverified"
    curl -fsSL -H "$auth" -H "Accept: application/octet-stream" "$url" -o "$archive"
    curl -fsSL -H "$auth" -H "Accept: application/octet-stream" "$sums_url" -o "$sums"
    source="SHA256SUMS of $release"
else
    if [ -n "$version" ]; then base="https://github.com/$REPO/releases/download/v$version"; else base="https://github.com/$REPO/releases/latest/download"; fi
    echo "Downloading $asset ($release)..."
    if command -v curl >/dev/null 2>&1; then fetch() { curl -fsSL "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then fetch() { wget -q "$1" -O "$2"; }
    else fail "curl or wget is required"; fi
    fetch "$base/$asset" "$archive"
    fetch "$base/SHA256SUMS" "$sums" || fail "$release of $REPO has no SHA256SUMS manifest; $unverified"
    source="$base/SHA256SUMS"
fi

if [ -n "$sums" ]; then
    expected=$(tr -d '\r' < "$sums" | awk -v a="$asset" '$2 == a || $2 == "*" a { print tolower($1); exit }')
    [ -n "$expected" ] || fail "SHA256SUMS lists no $asset; $unverified"
    if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$archive" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 "$archive" | awk '{ print $1 }')
    else fail "sha256sum or shasum is required to verify the download"; fi
    [ "$expected" = "$actual" ] || fail "checksum mismatch for $asset (expected $expected, got $actual); the download is corrupt or was altered"
fi

# The archive's SLSA build provenance through gh. Exit 1 with words other than these refuses: unrecognised is not a pass.
check_provenance() {
    if [ "${CORVUS_REQUIRE_ATTESTATION:-}" = 0 ]; then echo "Provenance not checked (CORVUS_REQUIRE_ATTESTATION=0)."; return; fi
    if ! command -v gh >/dev/null 2>&1; then reason="gh is not on PATH"
    else
        set -- attestation verify "$archive" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml"
        if [ -n "$tag" ]; then set -- "$@" --source-ref "refs/tags/$tag"; fi
        gh "$@" > "$tmp/gh.out" 2>&1 && code=0 || code=$?
        first=$(sed 's/^[[:space:]]*//; s/^Error: //' "$tmp/gh.out" | grep -v '^$' | head -n 1 || true)
        if [ "$code" = 0 ]; then echo "Provenance verified: $asset was built by $REPO's release workflow."; return; fi
        # gh's exit code 4: authentication required.
        if [ "$code" = 4 ]; then reason="gh is not signed in: gh auth login, or set GH_TOKEN"
        elif [ "$code" != 1 ] || grep -qiE 'unknown command|unknown flag|sigstore verifier|trusted root|dial tcp|no such host|connection refused|connection reset|i/o timeout|timed out|timeout exceeded|TLS handshake|proxyconnect|HTTP (401|403|429|5[0-9][0-9])' "$tmp/gh.out"; then reason="gh: $first"
        else fail "provenance check failed for $asset against $REPO's release workflow: $first"; fi
    fi
    [ "${CORVUS_REQUIRE_ATTESTATION:-}" != 1 ] || fail "provenance not checked ($reason) and CORVUS_REQUIRE_ATTESTATION=1; refusing to install"
    echo "Provenance not checked ($reason)."
}
check_provenance

# Runs the program's install with the terminal as input when there is one: piped into sh, stdin is this script.
register() {
    if [ ! -t 0 ] && (: < /dev/tty) 2>/dev/null; then
        # shellcheck disable=SC2086
        "$@" $setup_args < /dev/tty
    else
        # shellcheck disable=SC2086
        "$@" $setup_args
    fi
}

check_runs() {
    if ! version_found=$("$1" version); then
        if [ "$os" = linux-musl ]; then fail "the build needs the C++ runtime: apk add libstdc++ libgcc, then run this again"; fi
        fail "the downloaded build does not run on this machine"
    fi
}

if [ -n "$dry_run" ]; then
    # A staged copy outside the install root plans the registration for the program that would be installed.
    mkdir -p "$tmp/staged"
    tar -xzf "$archive" -C "$tmp/staged"
    chmod +x "$tmp/staged/corvus"
    check_runs "$tmp/staged/corvus"
    echo "Release: $release ($asset, Corvus $version_found)"
    echo "Checksum: $source"
    echo "Would install to: $ROOT/versions/$version_found, linked as $ROOT/current, with $BIN/corvus pointing at it"
    register "$tmp/staged/corvus" install --command "$EXE"
    exit 0
fi

mkdir -p "$ROOT/versions"
staging="$ROOT/versions/.new-$$"
rm -rf "$staging"
mkdir -p "$staging"
tar -xzf "$archive" -C "$staging"
chmod +x "$staging/corvus"
if ! version_found=$("$staging/corvus" version); then
    rm -rf "$staging"
    if [ "$os" = linux-musl ]; then fail "the build needs the C++ runtime: apk add libstdc++ libgcc, then run this again"; fi
    fail "the downloaded build does not run on this machine"
fi

target="$ROOT/versions/$version_found"
rm -rf "$target"
mv "$staging" "$target"
ln -sfn "$target" "$ROOT/current"
for dir in "$ROOT"/versions/*; do
    [ "$dir" = "$target" ] || rm -rf "$dir"
done

mkdir -p "$BIN"
ln -sf "$EXE" "$BIN/corvus"

echo "Installed Corvus $version_found to $target"
register "$EXE" install
echo
echo "Done. Commands: corvus status | update | uninstall"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "Add $BIN to PATH to run corvus from a terminal (the MCP clients do not need it)." ;;
esac
