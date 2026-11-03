#!/usr/bin/env bash
set -euo pipefail

# Only the disposable GitHub runner provisions this test authorization. Ghidra
# itself stays unprivileged and explicitly chooses the production pkexec path.
[[ ${GITHUB_ACTIONS:-} == true && $(id -u) != 0 && $# == 4 ]] || {
    echo 'requires an unprivileged disposable GitHub runner and four GUI fixture arguments' >&2
    exit 64
}
sudo -n true
command -v pkexec >/dev/null
command -v pkcheck >/dev/null
repository=$(realpath "$(dirname "$0")/../../..")
mkdir -p "$repository/build/test-results/gui-authorization"
work=$(mktemp -d "$repository/build/test-results/gui-authorization/run.XXXXXXXX")
policy="/etc/polkit-1/rules.d/00-forge-gui-$(basename "$work").rules"
cleanup() {
    local status=$?
    sudo -n rm -f -- "$policy" || status=1
    # Native validation retains private root-owned logs. Preserve them without
    # changing their permissions/ownership to make the artifact uploader happy.
    if [[ -d "$repository/build/test-results/gui-script-manager" ]]; then
        # The unprivileged caller deliberately owns the new diagnostic archive.
        # shellcheck disable=SC2024
        sudo -n tar -czf - -C "$repository/build/test-results/gui-script-manager" . \
            > "$work/gui-native-artifacts.tar.gz" || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
java=$(realpath "$(command -v "${JAVA_BIN:-java}")")
python3 - "$work/policy.rules" "$java" "$(id -un)" <<'PY'
import json
from pathlib import Path
import sys
destination, java, user = sys.argv[1:]
Path(destination).write_text('polkit.addRule(function(action, subject) {\n' +
    '    if (action.id === "org.freedesktop.policykit.exec" &&\n' +
    '        action.lookup("program") === ' + json.dumps(java) + ' &&\n' +
    '        subject.user === ' + json.dumps(user) + ') {\n' +
    '        return polkit.Result.YES;\n    }\n});\n')
PY
sudo -n install -o root -g root -m 0644 "$work/policy.rules" "$policy"
# A query containing action details requires a trusted caller. Query via the
# runner's existing sudo authority, but retain this unprivileged script PID as
# the subject. This does not launch Java or run Ghidra under sudo.
ready=0
for ((attempt=0; attempt<50; attempt++)); do
    # Diagnostic files deliberately remain owned by the unprivileged caller.
    # shellcheck disable=SC2024
    if sudo -n pkcheck --action-id org.freedesktop.policykit.exec --process "$$" \
        --detail program "$java" > "$work/policy-check.stdout" 2> "$work/policy-check.stderr"; then
        ready=1
        break
    fi
    sleep 0.1
done
if ((!ready)); then
    cat "$work/policy-check.stderr" >&2
    echo 'test authorization policy was not observed' >&2
    exit 1
fi
GHIDRA_GUI_NATIVE_ATTACHMENT=1 "$repository/src/test/integration/gui-script-manager.sh" "$@"
