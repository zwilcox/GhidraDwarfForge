#!/usr/bin/env bash
# Relocatable entry point for the private, checksum-pinned validation consumer.
set -euo pipefail

launcher=$(readlink -f -- "$0")
bundle=$(dirname -- "$(dirname -- "$launcher")")
configuration="$bundle/share/dwarfdump/dwarfdump.conf"
configuration_hash=842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef
if [[ ! -f "$configuration" || ! -r "$configuration" ]]; then
    echo 'validation dwarfdump configuration is missing or unreadable' >&2
    exit 1
fi
actual_hash=$(sha256sum < "$configuration")
if [[ "${actual_hash%% *}" != "$configuration_hash" ]]; then
    echo 'validation dwarfdump configuration checksum mismatch' >&2
    exit 1
fi
# The test consumer has one pinned configuration; do not silently select a
# different file through the upstream option aliases. Other tool flags pass on.
previous=
for argument in "$@"; do
    case "$argument" in
        --file-name*|-*xname=*)
            echo 'validation dwarfdump configuration overrides are unsupported' >&2
            exit 1
            ;;
        name=*)
            if [[ "$previous" == -*x && "$previous" != --* ]]; then
                echo 'validation dwarfdump configuration overrides are unsupported' >&2
                exit 1
            fi
            ;;
    esac
    previous=$argument
done
exec "$bundle/libexec/dwarfdump" "--file-name=$configuration" "$@"
