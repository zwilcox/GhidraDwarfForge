#!/usr/bin/env bash
set -uo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <result-directory> <command> [argument ...]" >&2
    exit 2
fi

result_directory=$1
shift
mkdir -p "$result_directory"
log_file="$result_directory/native-producer.log"
status_file="$result_directory/native-producer-status.txt"

set +e
"$@" 2>&1 | tee "$log_file"
command_status=${PIPESTATUS[0]}
set -e

printf 'exit_status=%d\n' "$command_status" > "$status_file"
if [[ "$command_status" -ne 0 ]]; then
    printf '%s\n' \
        "::error title=Isolated native producer failure::The isolated native producer process failed or crashed (exit status $command_status). See native-producer.log." \
        >&2
    exit "$command_status"
fi

printf '%s\n' 'isolated-native-producer=PASS' | tee -a "$status_file"
