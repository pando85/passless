#!/bin/bash
#
# Fixture command: emits only allowed redacted metadata.
# Reads sentinel file (if provided) and ensures none of its values appear
# in the output. Output contains only allowed metadata keys with redacted
# placeholder values.
#

set -euo pipefail

emit_redacted_metadata() {
    local sentinel_file="${1:-}"

    if [[ -n "$sentinel_file" ]] && [[ -f "$sentinel_file" ]]; then
        while IFS='=' read -r class value; do
            [[ -z "$class" || -z "$value" ]] && continue
            if grep -qF "$value" <<<"$(jq -n '{}')" 2>/dev/null; then
                echo "ERROR: sentinel value for '$class' would leak" >&2
                return 1
            fi
        done < "$sentinel_file"
    fi

    jq -n \
        --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        '{
            correlation_id: "corr-redacted-00000000",
            rp_id: "example.com",
            rp_name: "Example RP",
            user_name: "user-redacted",
            user_display_name: "Redacted User",
            session_id: "sess-redacted-00000000",
            endpoint_id: "ep-redacted-00000000",
            profile_id: "prof-redacted-00000000",
            intent_id: "intent-redacted-00000000",
            grant_id: "grant-redacted-00000000",
            device_name: "virtual-fido2",
            timestamp: $ts,
            status: "ok",
            error_code: "none",
            flow: "isolated",
            operation: "authenticate",
            redacted: true,
            present: true,
            approved: true,
            denied: false
        }'
}

if [[ "${1:-}" == "--sentinel-file" ]]; then
    emit_redacted_metadata "${2:-}"
else
    emit_redacted_metadata ""
fi
