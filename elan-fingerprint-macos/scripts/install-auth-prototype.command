#!/bin/bash
set -euo pipefail
PACKAGE_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_NAME="ELANFingerprintAuth.bundle"
SOURCE="$PACKAGE_DIR/$BUNDLE_NAME"
DEST="/Library/Security/SecurityAgentPlugins/$BUNDLE_NAME"
RIGHT="io.github.hackintosh-tools.elan-unlock.test"
ACTION="${1:---check}"

case "$ACTION" in
  --check)
    codesign --verify --strict "$SOURCE"
    plutil -lint "$PACKAGE_DIR/elan-auth-test-right.plist"
    if [[ -e "$DEST" ]]; then echo "Test plugin already exists: $DEST"; else echo "Test plugin is not installed"; fi
    if security authorizationdb read "$RIGHT" >/dev/null 2>&1; then echo "Test right already exists: $RIGHT"; else echo "Test right is not installed"; fi
    exit 0
    ;;
  --install|--update|--remove) ;;
  *) echo "Usage: $0 --check | --install | --update | --remove" >&2;exit 1;;
esac
if [[ "$(id -u)" != 0 ]]; then echo "Use sudo for $ACTION." >&2;exit 1;fi

if [[ "$ACTION" == --install ]]; then
    if [[ -e "$DEST" ]] || security authorizationdb read "$RIGHT" >/dev/null 2>&1; then
        echo "An ELAN test installation already exists; no files or rules were replaced." >&2;exit 1
    fi
    codesign --verify --strict "$SOURCE"
    mkdir -p /Library/Security/SecurityAgentPlugins
    ditto "$SOURCE" "$DEST"
    chown -R root:wheel "$DEST"
    chmod -R u+rwX,go+rX,go-w "$DEST"
    if ! security authorizationdb write "$RIGHT" < "$PACKAGE_DIR/elan-auth-test-right.plist"; then
        rm -rf "$DEST"
        echo "Test rule installation failed; the new plugin was removed." >&2;exit 1
    fi
    echo "Installed the isolated ELAN test plugin and right."
elif [[ "$ACTION" == --update ]]; then
    if [[ ! -d "$DEST" ]] || [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$DEST/Contents/Info.plist")" != io.github.hackintosh-tools.elan-auth ]]; then
        echo "The expected ELAN test plugin was not found; nothing replaced." >&2;exit 1
    fi
    codesign --verify --strict "$SOURCE"
    ELAN_BACKUP_HOME="$(/usr/bin/python3 -c 'import os,pwd; print(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir)')"
    BACKUP_ROOT="$ELAN_BACKUP_HOME/Desktop/ELAN 指纹适配/备份"
    BACKUP="$BACKUP_ROOT/ELAN-auth-plugin-backup-$(date +%Y%m%d-%H%M%S)"
    STAGE="/Library/Security/SecurityAgentPlugins/.ELANFingerprintAuth.pending.bundle"
    if [[ -e "$STAGE" ]] || [[ -e "$BACKUP" ]]; then echo "Update staging path already exists." >&2;exit 1;fi
    ditto "$SOURCE" "$STAGE"
    chown -R root:wheel "$STAGE"
    chmod -R u+rwX,go+rX,go-w "$STAGE"
    codesign --verify --strict "$STAGE"
    mkdir -p "$BACKUP_ROOT"
    chown "$SUDO_USER" "$(dirname "$BACKUP_ROOT")" "$BACKUP_ROOT"
    mkdir "$BACKUP"
    chown "$SUDO_USER" "$BACKUP"
    mv "$DEST" "$BACKUP/$BUNDLE_NAME"
    if ! mv "$STAGE" "$DEST"; then mv "$BACKUP/$BUNDLE_NAME" "$DEST";exit 1;fi
    echo "Updated the ELAN test plugin. Existing authorization rules were retained."
    echo "Previous plugin: $BACKUP/$BUNDLE_NAME"
else
    if [[ ! -d "$DEST" ]] || [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$DEST/Contents/Info.plist")" != io.github.hackintosh-tools.elan-auth ]]; then
        echo "The expected ELAN test plugin was not found; nothing removed." >&2;exit 1
    fi
    security authorizationdb remove "$RIGHT"
    rm -rf "$DEST"
    echo "Removed the ELAN test right and plugin."
fi
