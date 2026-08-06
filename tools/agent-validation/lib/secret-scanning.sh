#!/bin/bash
#
# Shared helpers for the secret-scanning stage
#

# shellcheck disable=SC2034
AV_LIB_SECRET_SCANNING_LOADED=true

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

AV_SENTINEL_CLASSES=(
    capability
    pin
    credential_id
    credential_ref
    user_handle
    client_data_hash
    cookie
    token
    private_key
)

AV_SENTINEL_PREFIX="AVSENT"

av_generate_sentinels() {
    local sentinel_file="$1"
    local nonce
    nonce=$(openssl rand -hex 8 2>/dev/null || date +%s%N)

    : > "$sentinel_file"
    chmod 600 "$sentinel_file"

    for class in "${AV_SENTINEL_CLASSES[@]}"; do
        local value
        value="${AV_SENTINEL_PREFIX}_${nonce}_$(openssl rand -hex 16 2>/dev/null || echo "${RANDOM}${RANDOM}${RANDOM}${RANDOM}")_${class}"
        printf '%s=%s\n' "$class" "$value" >> "$sentinel_file"
    done
}

av_load_sentinel() {
    local sentinel_file="$1"
    local class="$2"

    if [[ ! -f "$sentinel_file" ]]; then
        return 1
    fi

    local value
    value=$(grep "^${class}=" "$sentinel_file" 2>/dev/null | head -1 | cut -d= -f2-)
    if [[ -z "$value" ]]; then
        return 1
    fi
    printf '%s' "$value"
}

AV_ALLOWED_METADATA_KEYS=(
    correlation_id
    rp_id
    rp_name
    user_name
    user_display_name
    session_id
    endpoint_id
    profile_id
    intent_id
    grant_id
    device_name
    timestamp
    status
    error_code
    flow
    operation
    redacted
    present
    approved
    denied
)

AV_PROHIBITED_FIELD_NAMES=(
    pin
    pin_code
    pin_hash
    secret_key
    private_key
    capability_proof
    raw_capability
    auth_token
    pin_uv_auth_token
    claim_token
    credential_secret
    master_key
    wrap_key
)

av_scan_file_for_sentinels() {
    local file="$1"
    local sentinel_file="$2"
    local findings_file="$3"
    local found=0

    if [[ ! -f "$file" ]] || [[ ! -f "$sentinel_file" ]]; then
        return 0
    fi

    while IFS='=' read -r class value; do
        [[ -z "$class" || -z "$value" ]] && continue
        if grep -qF "$value" "$file" 2>/dev/null; then
            printf '%s\n' "{\"class\":\"${class}\",\"file\":\"$(av_json_escape "$file")\",\"match\":\"exact\"}" >> "$findings_file"
            ((found++)) || true
        fi
    done < "$sentinel_file"

    return $found
}

av_scan_file_for_prohibited_fields() {
    local file="$1"
    local findings_file="$2"
    local found=0

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    for field in "${AV_PROHIBITED_FIELD_NAMES[@]}"; do
        if grep -qiE "\"${field}\"\s*:\s*\"[^\"]+\"" "$file" 2>/dev/null; then
            printf '%s\n' "{\"field\":\"${field}\",\"file\":\"$(av_json_escape "$file")\",\"match\":\"prohibited_field\"}" >> "$findings_file"
            ((found++)) || true
        fi
    done

    return $found
}

av_scan_file_for_raw_payload_markers() {
    local file="$1"
    local findings_file="$2"
    local found=0

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    if grep -qE '"(raw_payload|raw_cbor|unredacted)"\s*:\s*"[^"]{8,}"' "$file" 2>/dev/null; then
        printf '%s\n' "{\"marker\":\"raw_payload\",\"file\":\"$(av_json_escape "$file")\",\"match\":\"raw_marker\"}" >> "$findings_file"
        ((found++)) || true
    fi

    return $found
}

av_is_allowed_metadata_key() {
    local key="$1"
    for allowed in "${AV_ALLOWED_METADATA_KEYS[@]}"; do
        if [[ "$key" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

av_scan_file_for_unknown_keys() {
    local file="$1"
    local findings_file="$2"
    local found=0

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    local keys
    keys=$(grep -oE '"[a-z_][a-z0-9_]*"\s*:' "$file" 2>/dev/null | sed 's/"//g;s/\s*://g' | sort -u) || true

    for key in $keys; do
        if ! av_is_allowed_metadata_key "$key"; then
            case "$key" in
                total|passed|failed|skipped|name|description|status|detail|timestamp|reason|error|scenarios|run_id|start_time|end_time|created|temp_root|resources|resource_count|finalized|cleanup_completed|git_commit|git_dirty|os|architecture|kernel_version|rust_version|cargo_version|systemd_version|chromium_version|cgroup_version|pass_version|gpg_version|swtpm_version|dbus_version|notify_daemon|stages|summary|title|required|error_msg|action|target|data|type|uid|connected|running|revoked|audit_gate_healthy|session_id|profile_id|endpoint_id|count)
                    continue
                    ;;
            esac
            printf '%s\n' "{\"key\":\"${key}\",\"file\":\"$(av_json_escape "$file")\",\"match\":\"unknown_key\"}" >> "$findings_file"
            ((found++)) || true
        fi
    done

    return $found
}
