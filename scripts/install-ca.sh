#!/usr/bin/env bash
# Install (or remove, with --uninstall) the adb CA into every trust store on
# this machine that a browser or app might consult.
#
# Linux has no single trust store. There are three kinds:
#   1. the OS store        /usr/local/share/ca-certificates  (needs root)
#      -> curl, wget, git, apt, python-requests, most CLI tools
#   2. Chrome/Chromium     ~/.pki/nssdb                      (NSS database)
#   3. Firefox             <profile>/cert9.db                (one per profile!)
#
# Firefox does NOT use the OS store by default, and a snap Firefox keeps its
# profiles somewhere completely different from a deb Firefox. If you have both
# installed you must do both.

set -uo pipefail

CA="${ADB_CA:-$HOME/.config/adb/ca.crt}"
NICK="adb Local CA"
UNINSTALL=0
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1

if [ ! -f "$CA" ]; then
    echo "no CA at $CA -- run './build/adb --print-ca' first" >&2
    exit 1
fi

# certutil ships with libnss3-tools; AdGuard also bundles a static copy.
CERTUTIL=""
for c in certutil /opt/adguard-cli/certutil /opt/AdGuardHome/certutil; do
    command -v "$c" >/dev/null 2>&1 && { CERTUTIL="$c"; break; }
    [ -x "$c" ] && { CERTUTIL="$c"; break; }
done

nss_apply() { # $1 = "sql:<dir>"
    local db="$1"
    if [ "$UNINSTALL" = 1 ]; then
        "$CERTUTIL" -D -n "$NICK" -d "$db" 2>/dev/null && echo "  removed  $db"
    else
        "$CERTUTIL" -A -n "$NICK" -t "C,," -i "$CA" -d "$db" 2>/dev/null &&
            echo "  trusted  $db" || echo "  FAILED   $db"
    fi
}

echo "CA: $CA"

if [ -z "$CERTUTIL" ]; then
    echo
    echo "certutil not found -- cannot script the browser stores."
    echo "  sudo apt install libnss3-tools"
    echo "or import $CA by hand:"
    echo "  Firefox: Settings > Privacy & Security > Certificates > View Certificates"
    echo "           > Authorities > Import > tick 'identify websites'"
    echo "  Chrome : chrome://certificate-manager > Local certificates > Installed by you"
else
    # ---- Chrome / Chromium / Edge / Brave --------------------------------
    echo
    echo "Chromium-family (~/.pki/nssdb):"
    mkdir -p "$HOME/.pki/nssdb"
    [ -f "$HOME/.pki/nssdb/cert9.db" ] ||
        "$CERTUTIL" -N -d "sql:$HOME/.pki/nssdb" --empty-password 2>/dev/null
    nss_apply "sql:$HOME/.pki/nssdb"

    # ---- Firefox: every profile of every install -------------------------
    echo
    echo "Firefox profiles:"
    found=0
    for root in "$HOME/.mozilla/firefox" \
                "$HOME/snap/firefox/common/.mozilla/firefox" \
                "$HOME/.var/app/org.mozilla.firefox/.mozilla/firefox"; do
        [ -d "$root" ] || continue
        for prof in "$root"/*/; do
            [ -f "$prof/cert9.db" ] || continue
            found=1
            nss_apply "sql:${prof%/}"
        done
    done
    [ "$found" = 0 ] && echo "  (none found)"
    echo
    echo "Firefox caches its trust list -- restart it for this to take effect."
fi

# ---- OS store (curl, wget, git, python, ...) -----------------------------
echo
echo "System store (curl/wget/git/python):"
DEST=/usr/local/share/ca-certificates/adb.crt
if [ "$UNINSTALL" = 1 ]; then
    echo "  sudo rm -f $DEST && sudo update-ca-certificates --fresh"
else
    echo "  sudo cp $CA $DEST && sudo update-ca-certificates"
fi
echo "  (needs root; skip it and pass --cacert $CA per-command instead)"
