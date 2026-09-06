#!/bin/sh
# Package built client binaries and a native menu-bar UI. No global install,
# launch, enrollment or changes to the user's selected agent happen here.
set -eu
script_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
prefix=${1:-"$script_dir/bin"}
conf=${2:-"$script_dir/team-relay.conf"}
bundle_id=${3:-io.teamrelay.desktop}
[ "$(uname -s)" = Darwin ] || { printf 'The menu-bar app requires macOS.\n' >&2; exit 1; }
command -v swiftc >/dev/null 2>&1 || { printf 'Install Apple Command Line Tools (xcode-select --install), then retry.\n' >&2; exit 1; }
bundle="$prefix/Team Relay.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$script_dir/desktop/macos/Info.plist" "$bundle/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :TeamRelayServiceConfig string $conf" "$bundle/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$bundle/Contents/Info.plist"
for binary in team-relay team-relay-agent team-relay-mcp; do
  cp "$prefix/$binary" "$bundle/Contents/Resources/$binary"
done
swiftc -O -target "$(uname -m)-apple-macos13.0" \
  -framework AppKit -framework ServiceManagement \
  "$script_dir/desktop/macos/TeamRelay.swift" -o "$bundle/Contents/MacOS/TeamRelay"
codesign --force --deep --sign - "$bundle" >/dev/null 2>&1
printf 'Menu-bar app ready: %s\n' "$bundle"
