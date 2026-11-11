#!/usr/bin/env bash
# Install apt packages, retrying transient update/install failures.
#
# GitHub Actions runners occasionally fail to resolve archive.ubuntu.com or
# security.ubuntu.com, which aborts the whole job. Retry a few times before
# giving up, and fail the step if every attempt fails.
#
# Usage: .ci/install-apt-packages.sh <package> [<package> ...]

set -euo pipefail

readonly MAX_ATTEMPTS=3
readonly RETRY_DELAY_SECONDS=10

if (( $# == 0 )); then
    echo "usage: ${0##*/} <package> [<package> ...]" >&2
    exit 2
fi

for (( attempt = 1; attempt <= MAX_ATTEMPTS; attempt++ )); do
    if sudo apt-get update && sudo apt-get install -y -- "$@"; then
        exit 0
    fi

    if (( attempt < MAX_ATTEMPTS )); then
        echo "apt-get failed (attempt ${attempt}/${MAX_ATTEMPTS}); retrying in ${RETRY_DELAY_SECONDS}s..." >&2
        sleep "$RETRY_DELAY_SECONDS"
    fi
done

echo "apt-get failed after ${MAX_ATTEMPTS} attempts" >&2
exit 1
