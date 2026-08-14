#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# == 3 ]] || { echo "usage: $0 ADB DEPLOY_HELPER SERVICE_TEMPLATE" >&2; exit 2; }
ADB="$1"
HELPER="$2"
SERVICE_TEMPLATE="$3"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

export HOME="$ROOT/home"
export XDG_CONFIG_HOME="$ROOT/config"
export XDG_DATA_HOME="$ROOT/data"
export XDG_STATE_HOME="$ROOT/state"
export MOCK_ROOT="$ROOT/mock"
export ADB_EXECUTABLE="$ADB"
export ADB_SHARE_DIR="$ROOT/share/adb"
mkdir -p "$HOME" "$MOCK_ROOT/bin" "$ADB_SHARE_DIR/systemd/user" "$ADB_SHARE_DIR/filters"
cp "$SERVICE_TEMPLATE" "$ADB_SHARE_DIR/systemd/user/adb.service"
printf '||ads.example^\n' > "$ADB_SHARE_DIR/filters/base.txt"

cat > "$MOCK_ROOT/bin/gsettings" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
file="$MOCK_ROOT/gsettings-${2//./_}-$3"
case "$1" in
get) cat "$file" ;;
set)
    value="$4"
    case "$3" in mode|host) [[ "$value" == \'* ]] || value="'$value'" ;; esac
    printf '%s\n' "$value" > "$file"
    ;;
*) exit 2 ;;
esac
MOCK

cat > "$MOCK_ROOT/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
shift # --user
case "${1:-}" in
daemon-reload) exit 0 ;;
is-active) [[ -f "$MOCK_ROOT/service-active" ]] ;;
enable)
    [[ "${MOCK_FAIL_ENABLE:-0}" == 0 ]] || exit 1
    : > "$MOCK_ROOT/service-active"
    ;;
disable) rm -f "$MOCK_ROOT/service-active" ;;
*) exit 2 ;;
esac
MOCK

cat > "$MOCK_ROOT/bin/certutil" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
mode="" input="" db=""
while (($#)); do
    case "$1" in
    -N|-A|-D|-L) mode="$1" ;;
    -i) input="$2"; shift ;;
    -d) db="$2"; shift ;;
    esac
    shift
done
directory="${db#sql:}"
case "$mode" in
-N) mkdir -p "$directory"; : > "$directory/cert9.db" ;;
-A) cp "$input" "$MOCK_ROOT/nss-cert.pem" ;;
-D) rm -f "$MOCK_ROOT/nss-cert.pem" ;;
-L) cat "$MOCK_ROOT/nss-cert.pem" ;;
*) exit 2 ;;
esac
MOCK

cat > "$MOCK_ROOT/bin/timeout" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$MOCK_ROOT/bin/"*
export PATH="$MOCK_ROOT/bin:/usr/bin:/bin"

set_value() {
    local schema="$1" key="$2" value="$3"
    printf '%s\n' "$value" > "$MOCK_ROOT/gsettings-${schema//./_}-$key"
}
get_value() {
    local schema="$1" key="$2"
    cat "$MOCK_ROOT/gsettings-${schema//./_}-$key"
}

set_value org.gnome.system.proxy mode "'auto'"
set_value org.gnome.system.proxy use-same-proxy false
set_value org.gnome.system.proxy.http enabled false
set_value org.gnome.system.proxy.http host "'old.proxy'"
set_value org.gnome.system.proxy.http port 3128
set_value org.gnome.system.proxy.https host "'secure.proxy'"
set_value org.gnome.system.proxy.https port 4443

"$HELPER" setup --yes
[[ "$(get_value org.gnome.system.proxy mode)" == "'manual'" ]]
[[ "$(get_value org.gnome.system.proxy.http host)" == "'127.0.0.1'" ]]
[[ -f "$MOCK_ROOT/service-active" ]]
[[ -f "$HOME/.pki/nssdb/cert9.db" ]]
[[ -f "$MOCK_ROOT/nss-cert.pem" ]]
[[ -f "$XDG_CONFIG_HOME/systemd/user/adb.service" ]]
installed_filters=("$XDG_DATA_HOME/adb/filters/"*.txt)
[[ -e "${installed_filters[0]}" ]]
[[ "$(stat -c '%a' "$XDG_CONFIG_HOME/adb/ca.key")" == 600 ]]

"$HELPER" setup --yes
status_output="$("$HELPER" status)"
[[ "$status_output" == *"service: active"* ]]
doctor_output="$("$HELPER" doctor)"
[[ "$doctor_output" == *"PASS desktop proxy points to the active listener"* ]]

"$HELPER" disable
[[ "$(get_value org.gnome.system.proxy mode)" == "'auto'" ]]
[[ "$(get_value org.gnome.system.proxy.http host)" == "'old.proxy'" ]]
[[ ! -f "$MOCK_ROOT/service-active" ]]
"$HELPER" disable
[[ "$(get_value org.gnome.system.proxy mode)" == "'auto'" ]]

"$HELPER" setup --yes
"$HELPER" uninstall --purge
[[ "$(get_value org.gnome.system.proxy mode)" == "'auto'" ]]
[[ ! -e "$XDG_CONFIG_HOME/systemd/user/adb.service" ]]
[[ ! -e "$MOCK_ROOT/nss-cert.pem" ]]
[[ ! -e "$XDG_CONFIG_HOME/adb/ca.key" ]]
[[ -e "$XDG_CONFIG_HOME/adb/custom.txt" ]]
"$HELPER" uninstall --purge

export MOCK_FAIL_ENABLE=1
if "$HELPER" setup --yes; then
    echo "setup unexpectedly succeeded with a failing service manager" >&2
    exit 1
fi
unset MOCK_FAIL_ENABLE
[[ "$(get_value org.gnome.system.proxy mode)" == "'auto'" ]]
[[ ! -f "$MOCK_ROOT/service-active" ]]
[[ ! -e "$MOCK_ROOT/nss-cert.pem" ]]
[[ ! -e "$XDG_STATE_HOME/adb/ca-consent.sha256" ]]

echo "deployment lifecycle integration test passed"
