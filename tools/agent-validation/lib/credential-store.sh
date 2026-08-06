#!/bin/bash
#
# Credential store manifest, agent state, and teardown helpers
# for the uninstall-rehearsal stage.
#
# No arbitrary command/eval/env command strings.
# All paths must be explicit validated absolute paths.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_CREDENTIAL_STORE_LOADED=true

AV_STORE_MAX_FILES=256
AV_STORE_MAX_BYTES=67108864

AV_ALLOWED_RESTART_MECHANISMS=("systemctl-user-passless" "systemctl-system-passless" "none")
AV_ALLOWED_STORE_FORMATS=("local-json")

av_validate_absolute_path() {
    local path="$1"
    local label="${2:-path}"

    if [[ -z "$path" ]]; then
        av_log_error "$label is empty"
        return 1
    fi

    if [[ "$path" != /* ]]; then
        av_log_error "$label must be absolute: $path"
        return 1
    fi

    if [[ -L "$path" ]]; then
        av_log_error "$label is a symlink (rejected): $path"
        return 1
    fi

    if [[ "$path" =~ \.\. ]]; then
        av_log_error "$label contains path traversal: $path"
        return 1
    fi

    return 0
}

av_validate_store_path() {
    local store_path="$1"

    if ! av_validate_absolute_path "$store_path" "credential store path"; then
        return 1
    fi

    if [[ ! -d "$store_path" ]]; then
        av_log_error "credential store directory does not exist: $store_path"
        return 1
    fi

    local resolved
    resolved=$(realpath "$store_path" 2>/dev/null) || {
        av_log_error "cannot resolve credential store path: $store_path"
        return 1
    }

    if [[ "$resolved" != "$store_path" ]]; then
        av_log_error "credential store path contains symlinks in chain: $store_path -> $resolved"
        return 1
    fi

    local file_count=0
    local total_bytes=0
    local f

    while IFS= read -r -d '' f; do
        if [[ -L "$f" ]]; then
            av_log_error "symlink found in credential store: $f"
            return 1
        fi

        if [[ -d "$f" ]]; then
            continue
        fi

        if [[ ! -f "$f" ]]; then
            av_log_error "special file found in credential store (not regular file or directory): $f"
            return 1
        fi

        ((file_count++)) || true

        if [[ $file_count -gt $AV_STORE_MAX_FILES ]]; then
            av_log_error "credential store exceeds max file count ($AV_STORE_MAX_FILES): $store_path"
            return 1
        fi

        local fsize
        fsize=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
        total_bytes=$((total_bytes + fsize))

        if [[ $total_bytes -gt $AV_STORE_MAX_BYTES ]]; then
            av_log_error "credential store exceeds max bytes ($AV_STORE_MAX_BYTES): $store_path"
            return 1
        fi
    done < <(find "$store_path" -mindepth 1 -print0 2>/dev/null)

    return 0
}

av_normalize_credential_json() {
    local file_path="$1"

    if ! jq empty "$file_path" 2>/dev/null; then
        av_log_error "not valid JSON: $file_path"
        return 1
    fi

    jq -c 'del(.sign_count)' "$file_path" 2>/dev/null || {
        av_log_error "failed to normalize JSON: $file_path"
        return 1
    }
}

av_extract_sign_count() {
    local file_path="$1"

    jq -r '.sign_count // empty' "$file_path" 2>/dev/null || echo ""
}

av_manifest_credential_store() {
    local store_path="$1"
    local output_file="$2"
    local store_format="${3:-local-json}"

    if ! av_validate_store_path "$store_path"; then
        return 1
    fi

    if [[ -z "$output_file" ]]; then
        av_log_error "manifest output file is required"
        return 1
    fi

    local format_valid=false
    local fmt
    for fmt in "${AV_ALLOWED_STORE_FORMATS[@]}"; do
        if [[ "$store_format" == "$fmt" ]]; then
            format_valid=true
            break
        fi
    done

    if [[ "$format_valid" != true ]]; then
        av_log_error "unsupported store format: $store_format (allowed: ${AV_ALLOWED_STORE_FORMATS[*]})"
        return 1
    fi

    local entries_json="[]"
    local file_count=0
    local total_bytes=0
    local f

    while IFS= read -r -d '' f; do
        [[ -d "$f" ]] && continue

        local rel_path="${f#"$store_path"/}"
        local fsize
        fsize=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
        local fmtime
        fmtime=$(stat -c '%Y' "$f" 2>/dev/null || echo 0)
        local fmode
        fmode=$(stat -c '%a' "$f" 2>/dev/null || echo 0)

        local semantic_hash=""
        local sign_count=""

        if [[ "$store_format" == "local-json" ]]; then
            semantic_hash=$(av_normalize_credential_json "$f" 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "unavailable")
            sign_count=$(av_extract_sign_count "$f" 2>/dev/null || echo "")
        else
            semantic_hash=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || echo "unavailable")
        fi

        entries_json=$(printf '%s' "$entries_json" | jq \
            --arg rel "$rel_path" \
            --argjson size "$fsize" \
            --arg mtime "$fmtime" \
            --arg mode "$fmode" \
            --arg semantic_hash "$semantic_hash" \
            --arg sign_count "$sign_count" \
            '. + [{"path": $rel, "size": $size, "mtime": $mtime, "mode": $mode, "semantic_hash": $semantic_hash, "sign_count": $sign_count}]')

        ((file_count++)) || true
        total_bytes=$((total_bytes + fsize))
    done < <(find "$store_path" -mindepth 1 -type f -print0 2>/dev/null | sort -z)

    local manifest_hash
    manifest_hash=$(printf '%s' "$entries_json" | jq -c '.' | sha256sum | cut -d' ' -f1)

    jq -n \
        --arg store_path "$store_path" \
        --arg store_format "$store_format" \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson file_count "$file_count" \
        --argjson total_bytes "$total_bytes" \
        --arg manifest_hash "$manifest_hash" \
        --argjson entries "$entries_json" \
        '{
            store_path: $store_path,
            store_format: $store_format,
            timestamp: $timestamp,
            file_count: $file_count,
            total_bytes: $total_bytes,
            manifest_hash: $manifest_hash,
            entries: $entries
        }' > "$output_file"

    av_log_info "Manifest: $file_count files, $total_bytes bytes, format=$store_format, hash=$manifest_hash"
    return 0
}

av_compare_store_manifests() {
    local pre_manifest="$1"
    local post_manifest="$2"
    local output_file="$3"

    if [[ ! -f "$pre_manifest" ]] || [[ ! -f "$post_manifest" ]]; then
        av_log_error "manifest files not found"
        return 1
    fi

    local pre_format post_format
    pre_format=$(jq -r '.store_format' "$pre_manifest")
    post_format=$(jq -r '.store_format' "$post_manifest")

    if [[ "$pre_format" != "local-json" ]] || [[ "$post_format" != "local-json" ]]; then
        av_log_error "unsupported store format for comparison: pre=$pre_format post=$post_format"
        return 1
    fi

    local pre_count post_count pre_bytes post_bytes
    pre_count=$(jq '.file_count' "$pre_manifest")
    post_count=$(jq '.file_count' "$post_manifest")
    pre_bytes=$(jq '.total_bytes' "$pre_manifest")
    post_bytes=$(jq '.total_bytes' "$post_manifest")

    local pre_hash post_hash
    pre_hash=$(jq -r '.manifest_hash' "$pre_manifest")
    post_hash=$(jq -r '.manifest_hash' "$post_manifest")

    local differences="[]"
    local sign_count_increases=0
    local unexpected_changes=0

    local pre_paths post_paths
    pre_paths=$(jq -r '.entries[].path' "$pre_manifest" | sort)
    post_paths=$(jq -r '.entries[].path' "$post_manifest" | sort)

    local added removed
    added=$(comm -13 <(echo "$pre_paths") <(echo "$post_paths") || true)
    removed=$(comm -23 <(echo "$pre_paths") <(echo "$post_paths") || true)

    if [[ -n "$added" ]]; then
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue
            differences=$(printf '%s' "$differences" | jq \
                --arg path "$p" --arg kind "added" \
                '. + [{"path": $path, "kind": $kind, "allowed": false}]')
            ((unexpected_changes++)) || true
        done <<< "$added"
    fi

    if [[ -n "$removed" ]]; then
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue
            differences=$(printf '%s' "$differences" | jq \
                --arg path "$p" --arg kind "removed" \
                '. + [{"path": $path, "kind": $kind, "allowed": false}]')
            ((unexpected_changes++)) || true
        done <<< "$removed"
    fi

    local common_paths
    common_paths=$(comm -12 <(echo "$pre_paths") <(echo "$post_paths") || true)

    if [[ -n "$common_paths" ]]; then
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue

            local pre_semantic post_semantic
            pre_semantic=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .semantic_hash' "$pre_manifest")
            post_semantic=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .semantic_hash' "$post_manifest")

            local pre_mtime post_mtime pre_mode post_mode pre_size post_size
            pre_mtime=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .mtime' "$pre_manifest")
            post_mtime=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .mtime' "$post_manifest")
            pre_mode=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .mode' "$pre_manifest")
            post_mode=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .mode' "$post_manifest")
            pre_size=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .size' "$pre_manifest")
            post_size=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .size' "$post_manifest")

            if [[ "$pre_semantic" != "$post_semantic" ]]; then
                differences=$(printf '%s' "$differences" | jq \
                    --arg path "$p" --arg kind "semantic_changed" \
                    '. + [{"path": $path, "kind": $kind, "allowed": false}]')
                ((unexpected_changes++)) || true
                continue
            fi

            local pre_sign post_sign
            pre_sign=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .sign_count' "$pre_manifest")
            post_sign=$(jq -r --arg path "$p" '.entries[] | select(.path == $path) | .sign_count' "$post_manifest")

            local counter_increased=false
            if [[ -n "$pre_sign" ]] && [[ -n "$post_sign" ]]; then
                if [[ "$pre_sign" =~ ^[0-9]+$ ]] && [[ "$post_sign" =~ ^[0-9]+$ ]]; then
                    if [[ "$post_sign" -gt "$pre_sign" ]]; then
                        counter_increased=true
                        ((sign_count_increases++)) || true
                        differences=$(printf '%s' "$differences" | jq \
                            --arg path "$p" --arg kind "sign_count_increased" \
                            --argjson from "$pre_sign" --argjson to "$post_sign" \
                            '. + [{"path": $path, "kind": $kind, "from": $from, "to": $to, "allowed": true}]')
                    elif [[ "$post_sign" -lt "$pre_sign" ]]; then
                        differences=$(printf '%s' "$differences" | jq \
                            --arg path "$p" --arg kind "sign_count_decreased" \
                            '. + [{"path": $path, "kind": $kind, "allowed": false}]')
                        ((unexpected_changes++)) || true
                    fi
                fi
            fi

            if [[ "$pre_mode" != "$post_mode" ]]; then
                differences=$(printf '%s' "$differences" | jq \
                    --arg path "$p" --arg kind "mode_changed" \
                    '. + [{"path": $path, "kind": $kind, "allowed": false}]')
                ((unexpected_changes++)) || true
            fi
            if [[ "$counter_increased" == false ]] \
                && { [[ "$pre_mtime" != "$post_mtime" ]] || [[ "$pre_size" != "$post_size" ]]; }; then
                differences=$(printf '%s' "$differences" | jq \
                    --arg path "$p" --arg kind "metadata_changed_without_counter" \
                    '. + [{"path": $path, "kind": $kind, "allowed": false}]')
                ((unexpected_changes++)) || true
            fi
        done <<< "$common_paths"
    fi

    local status="unchanged"
    if [[ $unexpected_changes -gt 0 ]]; then
        status="unexpected_changes"
    elif [[ $sign_count_increases -eq 1 ]]; then
        status="expected_single_sign_count_increase"
    elif [[ $sign_count_increases -gt 1 ]]; then
        status="multiple_sign_count_increases"
        ((unexpected_changes++)) || true
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg status "$status" \
        --argjson pre_file_count "$pre_count" \
        --argjson post_file_count "$post_count" \
        --argjson pre_bytes "$pre_bytes" \
        --argjson post_bytes "$post_bytes" \
        --arg pre_hash "$pre_hash" \
        --arg post_hash "$post_hash" \
        --argjson sign_count_increases "$sign_count_increases" \
        --argjson unexpected_changes "$unexpected_changes" \
        --argjson differences "$differences" \
        '{
            timestamp: $timestamp,
            status: $status,
            pre_file_count: $pre_file_count,
            post_file_count: $post_file_count,
            pre_bytes: $pre_bytes,
            post_bytes: $post_bytes,
            pre_manifest_hash: $pre_hash,
            post_manifest_hash: $post_hash,
            sign_count_increases: $sign_count_increases,
            unexpected_changes: $unexpected_changes,
            differences: $differences
        }' > "$output_file"

    if [[ $unexpected_changes -gt 0 ]]; then
        av_log_error "Store comparison: $unexpected_changes unexpected change(s)"
        return 1
    fi

    if [[ $sign_count_increases -ne 1 ]]; then
        av_log_error "Store comparison: expected exactly 1 sign_count increase, got $sign_count_increases"
        return 1
    fi

    return 0
}

av_record_agent_state() {
    local passless_bin="$1"
    local profile_id="$2"
    local output_file="$3"
    local use_sudo="${4:-0}"

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not executable: $passless_bin"
        return 1
    fi

    if [[ -z "$profile_id" ]]; then
        av_log_error "profile_id is required"
        return 1
    fi

    local cmd_prefix=()
    if [[ "$use_sudo" == "1" ]]; then
        if ! av_check_sudo_binary_exists; then
            av_log_error "sudo requested but not available"
            return 1
        fi
        cmd_prefix=(sudo --)
    fi

    local session_json="[]"
    local session_output
    if session_output=$("${cmd_prefix[@]}" "$passless_bin" agent-admin --output json session list --profile "$profile_id" 2>/dev/null); then
        session_json=$(printf '%s' "$session_output" | jq -c '.sessions // []' 2>/dev/null || echo "[]")
    fi

    local delegation_json="[]"
    local delegation_output
    if delegation_output=$("${cmd_prefix[@]}" "$passless_bin" agent-admin --output json delegation list --profile "$profile_id" 2>/dev/null); then
        delegation_json=$(printf '%s' "$delegation_output" | jq -c '.grants // []' 2>/dev/null || echo "[]")
    fi

    local profile_json="{}"
    local profile_output
    if profile_output=$("${cmd_prefix[@]}" "$passless_bin" agent-admin --output json profile check "$profile_id" 2>/dev/null); then
        profile_json=$(printf '%s' "$profile_output" | jq -c '.' 2>/dev/null || echo "{}")
    fi

    if ! jq -e --arg profile "$profile_id" \
        '(.profile_id == $profile) and (.profile.profile_id == $profile) and
         (.sessions | type == "array") and (.delegations | type == "array")' \
        < <(jq -n --arg profile_id "$profile_id" --argjson sessions "$session_json" \
            --argjson delegations "$delegation_json" --argjson profile "$profile_json" \
            '{profile_id:$profile_id,sessions:$sessions,delegations:$delegations,profile:$profile}') \
        >/dev/null; then
        av_log_error "agent state responses were incomplete for profile: $profile_id"
        return 1
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg profile_id "$profile_id" \
        --argjson sessions "$session_json" \
        --argjson delegations "$delegation_json" \
        --argjson profile "$profile_json" \
        '{
            timestamp: $timestamp,
            profile_id: $profile_id,
            sessions: $sessions,
            delegations: $delegations,
            profile: $profile
        }' > "$output_file"

    av_log_info "Agent state recorded: sessions=$(printf '%s' "$session_json" | jq 'length'), delegations=$(printf '%s' "$delegation_json" | jq 'length')"
    return 0
}

av_disable_agent_profile() {
    local passless_bin="$1"
    local profile_id="$2"
    local use_sudo="${3:-0}"

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not executable: $passless_bin"
        return 1
    fi

    local cmd_prefix=()
    if [[ "$use_sudo" == "1" ]]; then
        if ! av_check_sudo_binary_exists; then
            av_log_error "sudo requested but not available"
            return 1
        fi
        cmd_prefix=(sudo --)
    fi

    local output
    if ! output=$("${cmd_prefix[@]}" "$passless_bin" agent-admin --output json profile disable "$profile_id" 2>/dev/null); then
        av_log_error "profile disable failed for: $profile_id"
        return 1
    fi

    local disabled
    disabled=$(printf '%s' "$output" | jq -r 'if has("enabled") then .enabled else true end' \
        2>/dev/null || echo "true")
    if [[ "$disabled" != "false" ]]; then
        av_log_error "profile disable returned enabled=$disabled"
        return 1
    fi

    av_log_info "Profile disabled: $profile_id"
    return 0
}

av_revoke_agent_sessions() {
    local passless_bin="$1"
    local profile_id="$2"
    local state_file="$3"
    local use_sudo="${4:-0}"

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not executable: $passless_bin"
        return 1
    fi

    local cmd_prefix=()
    if [[ "$use_sudo" == "1" ]]; then
        if ! av_check_sudo_binary_exists; then
            av_log_error "sudo requested but not available"
            return 1
        fi
        cmd_prefix=(sudo --)
    fi

    local revoked_count=0
    local revoke_failed=false

    if [[ -f "$state_file" ]]; then
        local session_ids
        session_ids=$(jq -r '.sessions[]?.session_id // empty' "$state_file" 2>/dev/null || echo "")

        if [[ -n "$session_ids" ]]; then
            while IFS= read -r sid; do
                [[ -z "$sid" ]] && continue
                if "${cmd_prefix[@]}" "$passless_bin" agent-admin --output json session revoke "$sid" --confirm >/dev/null 2>&1; then
                    ((revoked_count++)) || true
                else
                    av_log_warn "session revoke failed for: $sid"
                    revoke_failed=true
                fi
            done <<< "$session_ids"
        fi

        local grant_ids
        grant_ids=$(jq -r '.delegations[]?.grant_id // empty' "$state_file" 2>/dev/null || echo "")

        if [[ -n "$grant_ids" ]]; then
            while IFS= read -r gid; do
                [[ -z "$gid" ]] && continue
                if "${cmd_prefix[@]}" "$passless_bin" agent-admin --output json delegation revoke "$gid" --confirm >/dev/null 2>&1; then
                    ((revoked_count++)) || true
                else
                    av_log_warn "delegation revoke failed for: $gid"
                    revoke_failed=true
                fi
            done <<< "$grant_ids"
        fi
    fi

    av_log_info "Revoked $revoked_count session(s)/grant(s)"
    [[ "$revoke_failed" == false ]]
}

av_shutdown_agent_daemon() {
    local passless_bin="$1"
    local use_sudo="${2:-0}"

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not executable: $passless_bin"
        return 1
    fi

    local cmd_prefix=()
    if [[ "$use_sudo" == "1" ]]; then
        if ! av_check_sudo_binary_exists; then
            av_log_error "sudo requested but not available"
            return 1
        fi
        cmd_prefix=(sudo --)
    fi

    local output
    if ! output=$("${cmd_prefix[@]}" "$passless_bin" agent-admin --output json shutdown --confirm 2>/dev/null); then
        av_log_error "daemon shutdown command failed"
        return 1
    fi
    if ! jq -e '.shutdown_initiated == true' <<<"$output" >/dev/null; then
        av_log_error "daemon shutdown response was not accepted"
        return 1
    fi

    av_log_info "Agent daemon shutdown issued"
    return 0
}

av_remove_test_udev_artifacts() {
    local registered_resources_file="$1"
    local removed_count=0

    if [[ ! -f "$registered_resources_file" ]]; then
        av_log_warn "no registered resources file found"
        return 0
    fi

    local resource_paths
    resource_paths=$(jq -r '.resources[]? |
        select((.type == "test_udev_rule") or (.action == "remove_test_udev_rule")) |
        (.path // .target // empty)' "$registered_resources_file" 2>/dev/null || echo "")

    if [[ -n "$resource_paths" ]]; then
        while IFS= read -r rule_file; do
            [[ -z "$rule_file" ]] && continue

            if [[ ! "$rule_file" =~ ^/etc/udev/rules.d/99-agent-validation-test-[a-zA-Z0-9][a-zA-Z0-9._-]{0,255}\.rules$ ]] \
                || [[ "$(basename "$rule_file")" == *..* ]]; then
                av_log_error "invalid state-recorded udev rule: $rule_file"
                return 1
            fi

            if [[ ! -f "$rule_file" ]]; then
                continue
            fi

            if [[ -L "$rule_file" ]]; then
                av_log_error "refusing to remove symlink udev rule: $rule_file"
                return 1
            fi

            if [[ $EUID -eq 0 ]]; then
                rm -f -- "$rule_file"
            elif av_check_sudo_binary_exists; then
                sudo -- rm -f -- "$rule_file"
            else
                av_log_warn "cannot remove test udev rule (no sudo): $rule_file"
                continue
            fi
            ((removed_count++)) || true
        done <<< "$resource_paths"

        if [[ $removed_count -gt 0 ]]; then
            if [[ $EUID -eq 0 ]]; then
                udevadm control --reload-rules
            elif av_check_sudo_binary_exists; then
                sudo -- udevadm control --reload-rules
            fi
        fi
    fi

    av_log_info "Removed $removed_count test udev artifact(s)"
    return 0
}

av_restart_human_authenticator() {
    local mechanism="$1"

    local mechanism_valid=false
    local allowed
    for allowed in "${AV_ALLOWED_RESTART_MECHANISMS[@]}"; do
        if [[ "$mechanism" == "$allowed" ]]; then
            mechanism_valid=true
            break
        fi
    done

    if [[ "$mechanism_valid" != true ]]; then
        av_log_error "invalid restart mechanism: $mechanism (allowed: ${AV_ALLOWED_RESTART_MECHANISMS[*]})"
        return 1
    fi

    case "$mechanism" in
        systemctl-user-passless)
            if ! command -v systemctl &>/dev/null; then
                av_log_error "systemctl not available"
                return 1
            fi
            systemctl --user restart passless 2>/dev/null || {
                av_log_error "systemctl --user restart passless failed"
                return 1
            }
            ;;
        systemctl-system-passless)
            if ! command -v systemctl &>/dev/null || ! av_check_sudo_binary_exists; then
                av_log_error "systemctl and sudo are required"
                return 1
            fi
            sudo -- systemctl restart passless.service || {
                av_log_error "systemctl restart passless.service failed"
                return 1
            }
            ;;
        none)
            av_log_info "restart mechanism is 'none'; skipping restart"
            return 0
            ;;
    esac

    av_log_info "Human authenticator restarted via: $mechanism"
    return 0
}

av_verify_agent_absent() {
    local passless_bin="$1"
    local profile_id="$2"
    local agent_runtime_dir="${3:-}"
    local output_file="$4"

    local checks_json="[]"
    local violations=0

    add_check() {
        local check="$1" name="$2" status="$3" detail="$4"
        checks_json=$(printf '%s' "$checks_json" | jq \
            --arg c "$check" --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"check": $c, "name": $n, "status": $s, "detail": $d}]')
    }

    if "$passless_bin" agent-admin --output json profile check "$profile_id" &>/dev/null; then
        add_check "AGENT-01" "profile_absent" "fail" "agent profile remains reachable"
        ((violations++)) || true
    else
        add_check "AGENT-01" "profile_absent" "pass" "agent profile is not reachable"
    fi

    if [[ -n "$agent_runtime_dir" ]] && [[ -d "$agent_runtime_dir" ]]; then
        local socket_count
        socket_count=$(find "$agent_runtime_dir" -xdev \( -type s -o -name '*.sock' -o -name '*.socket' \) \
            -print 2>/dev/null | wc -l)
        if [[ $socket_count -gt 0 ]]; then
            add_check "AGENT-02" "agent_sockets" "fail" "$socket_count socket(s) remain"
            ((violations++)) || true
        else
            add_check "AGENT-02" "agent_sockets" "pass" "no agent sockets"
        fi
    else
        add_check "AGENT-02" "agent_sockets" "pass" "runtime dir absent or not specified"
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson violations "$violations" \
        --argjson checks "$checks_json" \
        '{timestamp: $timestamp, violations: $violations, checks: $checks}' > "$output_file"

    if [[ $violations -gt 0 ]]; then
        return 1
    fi
    return 0
}

av_verify_human_intact() {
    local human_store_path="$1"
    local passless_bin="$2"
    local output_file="$3"

    local checks_json="[]"
    local violations=0

    add_check() {
        local check="$1" name="$2" status="$3" detail="$4"
        checks_json=$(printf '%s' "$checks_json" | jq \
            --arg c "$check" --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"check": $c, "name": $n, "status": $s, "detail": $d}]')
    }

    if [[ ! -d "$human_store_path" ]]; then
        add_check "HUMAN-01" "store_exists" "fail" "human store missing: $human_store_path"
        ((violations++)) || true
    else
        local file_count
        file_count=$(find "$human_store_path" -mindepth 1 -type f 2>/dev/null | wc -l)
        if [[ $file_count -gt 0 ]]; then
            add_check "HUMAN-01" "store_exists" "pass" "$file_count file(s) present"
        else
            add_check "HUMAN-01" "store_exists" "fail" "human store is empty"
            ((violations++)) || true
        fi
    fi

    if [[ -x "$passless_bin" ]]; then
        if pgrep -f "passless" &>/dev/null; then
            add_check "HUMAN-02" "human_process" "pass" "passless process running"
        else
            add_check "HUMAN-02" "human_process" "fail" "no passless process found"
            ((violations++)) || true
        fi
    else
        add_check "HUMAN-02" "human_process" "skip" "passless binary not available"
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson violations "$violations" \
        --argjson checks "$checks_json" \
        '{timestamp: $timestamp, violations: $violations, checks: $checks}' > "$output_file"

    if [[ $violations -gt 0 ]]; then
        return 1
    fi
    return 0
}
