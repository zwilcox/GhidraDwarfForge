#!/usr/bin/env bash
# Each integration group runs on its own Ubuntu runner.
set -euo pipefail

diagnostics=build/test-results/target-toolchain
mkdir -p "$diagnostics"
log=$(mktemp)
trap 'rm -f "$log"' EXIT

# Retry only the network phases. A second attempt can reuse complete or
# partial downloads from the first. Stagger retries from parallel groups.
fetch() {
    local phase=$1 status attempt
    shift
    for attempt in 1 2; do
        if sudo timeout --kill-after=15s 10m apt-get \
                -o Acquire::Retries=3 -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 "$@" 2>&1 \
                | tee "$log"; then
            status=0
        else
            status=$?
        fi
        tail -c 16384 "$log" > "$diagnostics/$phase-$attempt.log"
        if [[ $status == 0 ]]; then
            return 0
        fi
        if [[ $attempt == 1 ]]; then
            sleep "$((30 + RANDOM % 31))"
        fi
    done
    return "$status"
}

fetch indexes -o APT::Update::Error-Mode=any update
fetch packages --download-only install --no-install-recommends -y "$@"
sudo apt-get --no-download install --no-install-recommends -y "$@"
