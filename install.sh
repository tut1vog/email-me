#!/bin/sh
# Installs or updates the email-me binary on macOS or Linux from the GitHub
# releases. Run it again to update:
#
#   curl -fsSL https://github.com/tut1vog/email-me/releases/latest/download/install.sh | sh
#
# Environment:
#   EMAIL_ME_VERSION      release tag to install, e.g. v1.2.3 (default: the latest release)
#   EMAIL_ME_INSTALL_DIR  directory for the binary (default: where email-me already
#                         is on PATH, else ~/.local/bin)
#
# The download is checked against the release's checksums.txt. sudo is used
# only when the directory is not writable.

set -eu

repo=tut1vog/email-me

say() { printf 'email-me: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

# fetch URL FILE downloads URL to FILE, or to stdout when FILE is -.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	else
		die "sha256sum or shasum is required to verify the download"
	fi
}

detect_platform() {
	case $(uname -s) in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "unsupported OS $(uname -s); use the Docker image instead" ;;
	esac
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m); use the Docker image instead" ;;
	esac
	# A shell under Rosetta reports x86_64 on Apple silicon.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] &&
		[ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = 1 ]; then
		arch=arm64
	fi
}

latest_version() {
	fetch "https://api.github.com/repos/$repo/releases/latest" - |
		sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

main() {
	detect_platform

	version=${EMAIL_ME_VERSION:-}
	if [ -z "$version" ]; then
		version=$(latest_version) || true
		[ -n "$version" ] || die "could not find the latest release of $repo"
	fi

	dir=${EMAIL_ME_INSTALL_DIR:-}
	if [ -z "$dir" ]; then
		if existing=$(command -v email-me 2>/dev/null) && [ -n "$existing" ]; then
			dir=$(dirname "$existing")
		else
			dir=$HOME/.local/bin
		fi
	fi
	target=$dir/email-me

	current=
	if [ -x "$target" ]; then
		current=$("$target" version 2>/dev/null) || current=
		if [ "$current" = "$version" ]; then
			say "$version is already installed at $target"
			return
		fi
	fi

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	asset=email-me_${os}_${arch}.tar.gz
	base=https://github.com/$repo/releases/download/$version
	say "downloading $version for $os/$arch"
	fetch "$base/$asset" "$tmp/$asset" || die "could not download $base/$asset"
	fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "could not download $base/checksums.txt"

	want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
	[ -n "$want" ] || die "$asset is not listed in checksums.txt"
	[ "$(sha256 "$tmp/$asset")" = "$want" ] || die "checksum mismatch for $asset"

	tar -xzf "$tmp/$asset" -C "$tmp" email-me
	chmod 755 "$tmp/email-me"

	sudo=
	if ! mkdir -p "$dir" 2>/dev/null || [ ! -w "$dir" ]; then
		if [ "$(id -u)" = 0 ] || ! command -v sudo >/dev/null 2>&1; then
			die "$dir is not writable"
		fi
		say "$dir is not writable; using sudo"
		sudo=sudo
		$sudo mkdir -p "$dir"
	fi
	# Copy next to the target, then rename over it: a running email-me keeps
	# its old file, and the new one appears whole.
	$sudo cp "$tmp/email-me" "$dir/.email-me.new"
	$sudo mv -f "$dir/.email-me.new" "$target"

	if [ -n "$current" ]; then
		say "updated $target from $current to $version; run email-me restart to run it"
	else
		say "installed $version at $target; run email-me start"
	fi
	case :$PATH: in
	*:"$dir":*) ;;
	*) say "$dir is not on your PATH; add it, e.g. export PATH=\"$dir:\$PATH\"" ;;
	esac
}

main "$@"
