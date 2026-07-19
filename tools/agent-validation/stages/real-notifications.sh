#!/bin/bash
#
# Tier 2 Stage: Real Notifications
#
# Uses the production agent-prompt-probe binary (built with agent-validation feature)
# as the subject under test inside isolated dbus-run-session + Xvfb + dunst sessions.
#
# Scenarios (each in its own isolated session):
#   delayed_approve    => Approved  (approve after min_review_delay elapsed)
#   premature_approve  => Denied    (approve before min_review_delay elapsed)
#   deny               => Denied    (explicit deny action)
#   close              => Timeout   (notification closed/expired without action)
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_NOTIFICATIONS_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/notifications.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_REAL_NOTIFICATIONS_LOADED=true

_RN_PROBE_TIMEOUT=15
_RN_MIN_REVIEW_DELAY_MS=2000
_RN_NOTIFY_WAIT_SECS=10
_RN_PREMATURE_DELAY_MS=200
_RN_DELAYED_EXTRA_MS=3000

_av_rn_json_array="[]"
_av_rn_total=0
_av_rn_passed=0
_av_rn_failed=0
_av_rn_skipped=0

_av_rn_add_scenario() {
    local scenario_name="$1" scenario_status="$2" scenario_detail="$3"
    _av_rn_json_array=$(printf '%s' "$_av_rn_json_array" | jq \
        --arg n "$scenario_name" --arg s "$scenario_status" --arg d "$scenario_detail" \
        '. + [{"name": $n, "status": $s, "detail": $d}]')
    ((_av_rn_total++)) || true
    case "$scenario_status" in
        pass) ((_av_rn_passed++)) || true ;;
        fail) ((_av_rn_failed++)) || true ;;
        skip) ((_av_rn_skipped++)) || true ;;
    esac
}

_av_rn_write_results() {
    local results_file="$1"
    local overall="pass"
    if [[ "$_av_rn_failed" -gt 0 ]]; then
        overall="fail"
    elif [[ "$_av_rn_skipped" -eq "$_av_rn_total" ]] && [[ "$_av_rn_total" -gt 0 ]]; then
        overall="skip"
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg status "$overall" \
        --argjson total "$_av_rn_total" \
        --argjson passed "$_av_rn_passed" \
        --argjson failed "$_av_rn_failed" \
        --argjson skipped "$_av_rn_skipped" \
        --argjson scenarios "$_av_rn_json_array" \
        '{timestamp: $timestamp, status: $status,
          total: $total, passed: $passed, failed: $failed, skipped: $skipped,
          scenarios: $scenarios}' > "$results_file"
}

_av_rn_run_scenario() {
    local scenario_name="$1"
    local action_kind="$2"
    local expected_decision="$3"
    local display_num="$4"
    local probe_bin="$5"

    local session_dir="${TEMP_ROOT:-/tmp}/rn-session-$$-${scenario_name}"
    mkdir -p "$session_dir"
    chmod 700 "$session_dir"

    local probe_output="${session_dir}/probe.json"
    local dunst_config="${session_dir}/dunstrc"
    local session_log="${session_dir}/session.log"

    cat > "$dunst_config" << 'DUNST_EOF'
[dunst]
follow = mouse
indicate_hidden = yes
shrink = no
transparency = 0
notification_height = 0
separator_height = 2
padding = 8
horizontal_padding = 8
frame_width = 3
sort = yes
idle_threshold = 120
font = Monospace 10
line_height = 0
markup = full
format = "<b>%s</b>\n%b"
alignment = left
show_age_threshold = 60
expire_timeout = 0
ignore_newline = no
stack_duplicates = false
hide_duplicate_count = false
show_indicators = yes
icon_position = left
max_icon_size = 32
sticky_history = yes
history_length = 20
startup_notification = false
verbosity = mesg
corner_radius = 0
mouse_left_click = do_action
mouse_middle_click = close_all
mouse_right_click = close_current

[experimental]
per_monitor_dpi = false

[urgency_low]
background = "#222222"
foreground = "#888888"
timeout = 0

[urgency_normal]
background = "#1c1f22"
foreground = "#ffffff"
timeout = 0

[urgency_critical]
background = "#900000"
foreground = "#ffffff"
frame_color = "#ff0000"
timeout = 0
DUNST_EOF

    local driver_script="${session_dir}/driver.sh"
    cat > "$driver_script" << DRIVER_EOF
#!/bin/bash
set -euo pipefail
export DISPLAY="${display_num}"

dunst -config "${dunst_config}" &
dunst_pid=\$!

_wait_for_dunst() {
    local w=0
    while [[ \$w -lt 20 ]]; do
        if dunstctl running 2>/dev/null | grep -qi 'true\|running\|1'; then
            return 0
        fi
        local c
        c=\$(dunstctl count 2>/dev/null || echo "0")
        if [[ "\$c" =~ ^[0-9]+\$ ]]; then
            return 0
        fi
        sleep 0.25
        ((w++)) || true
    done
    return 1
}

if ! _wait_for_dunst; then
    echo '{"decision":"error","error_kind":"notification_unsupported","latency_class":"fast"}' > "${probe_output}"
    kill \$dunst_pid 2>/dev/null || true
    exit 0
fi

"${probe_bin}" --timeout ${_RN_PROBE_TIMEOUT} --min-review-delay ${_RN_MIN_REVIEW_DELAY_MS} > "${probe_output}" 2>"${session_dir}/probe.stderr" &
probe_pid=\$!

waited=0
while [[ \$waited -lt ${_RN_NOTIFY_WAIT_SECS} ]]; do
    cnt=\$(dunstctl count 2>/dev/null || echo "0")
    if [[ "\$cnt" =~ ^[0-9]+\$ ]] && [[ "\$cnt" -gt 0 ]]; then
        break
    fi
    if dunstctl history 2>/dev/null | grep -q "Passless"; then
        break
    fi
    if ! kill -0 \$probe_pid 2>/dev/null; then
        break
    fi
    sleep 0.2
    ((waited++)) || true
done

case "${action_kind}" in
    delayed_approve)
        sleep \$((_RN_DELAYED_EXTRA_MS / 1000)).\$((_RN_DELAYED_EXTRA_MS % 1000))
        dunstctl action 0 2>/dev/null || true
        ;;
    premature_approve)
        sleep 0.\$(printf '%01d' \$((_RN_PREMATURE_DELAY_MS / 100)))
        dunstctl action 0 2>/dev/null || true
        ;;
    deny)
        sleep 0.5
        dunstctl action 1 2>/dev/null || true
        ;;
    close)
        sleep 0.5
        dunstctl close 2>/dev/null || true
        ;;
esac

poll=0
while [[ \$poll -lt $((_RN_PROBE_TIMEOUT + 5)) ]]; do
    if ! kill -0 \$probe_pid 2>/dev/null; then
        break
    fi
    if [[ -s "${probe_output}" ]]; then
        break
    fi
    sleep 0.3
    ((poll++)) || true
done

if kill -0 \$probe_pid 2>/dev/null; then
    kill \$probe_pid 2>/dev/null || true
    wait \$probe_pid 2>/dev/null || true
fi

kill \$dunst_pid 2>/dev/null || true
wait \$dunst_pid 2>/dev/null || true
DRIVER_EOF
    chmod +x "$driver_script"

    local exit_code=0
    dbus-run-session -- bash "$driver_script" > "$session_log" 2>&1 || exit_code=$?

    if [[ ! -s "$probe_output" ]]; then
        printf '{"decision":"error","error_kind":"render_failed","latency_class":"fast"}' > "$probe_output"
    fi

    local actual_decision
    actual_decision=$(jq -r '.decision // "error"' "$probe_output" 2>/dev/null || echo "error")

    if [[ "$actual_decision" == "$expected_decision" ]]; then
        _av_rn_add_scenario "$scenario_name" "pass" \
            "expected=${expected_decision} actual=${actual_decision} (exit=${exit_code})"
    else
        _av_rn_add_scenario "$scenario_name" "fail" \
            "expected=${expected_decision} actual=${actual_decision} (exit=${exit_code})"
    fi

    if [[ -f "${EVIDENCE_DIR:-/tmp}/rn-evidence-${scenario_name}.json" ]] || true; then
        cp "$probe_output" "${EVIDENCE_DIR:-/tmp}/rn-evidence-${scenario_name}.json" 2>/dev/null || true
        cp "$session_log" "${EVIDENCE_DIR:-/tmp}/rn-evidence-${scenario_name}.log" 2>/dev/null || true
    fi

    rm -rf "$session_dir" 2>/dev/null || true
}

stage_real_notifications() {
    local results_file="${EVIDENCE_DIR:-/tmp}/real-notifications-results.json"
    _av_rn_json_array="[]"
    _av_rn_total=0
    _av_rn_passed=0
    _av_rn_failed=0
    _av_rn_skipped=0

    av_log_info "Checking notification prerequisites..."

    if ! av_notification_prereqs_check 2>/dev/null; then
        av_log_warn "Notification prerequisites not met; skipping"
        _av_rn_add_scenario "prerequisites" "skip" "dunst/dunstctl/Xvfb/dbus-run-session not available"
        _av_rn_write_results "$results_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    _av_rn_add_scenario "prerequisites" "pass" "dunst/dunstctl/Xvfb/dbus-run-session available"

    local probe_bin
    if ! probe_bin=$(av_probe_binary); then
        av_log_warn "agent-prompt-probe binary not found; skipping"
        _av_rn_add_scenario "probe_binary" "skip" "agent-prompt-probe not found (build with --features agent-validation)"
        _av_rn_write_results "$results_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    _av_rn_add_scenario "probe_binary" "pass" "probe at ${probe_bin}"

    if ! av_dunst_supports_actions 2>/dev/null; then
        av_log_warn "dunst does not support action API; skipping action scenarios"
        _av_rn_add_scenario "action_api" "skip" "dunstctl action not supported"
        _av_rn_write_results "$results_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    _av_rn_add_scenario "action_api" "pass" "dunstctl action supported"

    local display
    if ! display=$(av_next_xvfb_display); then
        av_log_warn "No free Xvfb display available; skipping"
        _av_rn_add_scenario "xvfb_display" "skip" "no free display"
        _av_rn_write_results "$results_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    av_log_info "Running isolated notification scenarios on ${display}..."

    _av_rn_run_scenario "delayed_approve"    "delayed_approve"   "approved"  "$display" "$probe_bin"
    _av_rn_run_scenario "premature_approve"  "premature_approve" "denied"    "$display" "$probe_bin"
    _av_rn_run_scenario "deny"               "deny"              "denied"    "$display" "$probe_bin"
    _av_rn_run_scenario "close"              "close"             "timeout"   "$display" "$probe_bin"

    _av_rn_write_results "$results_file"

    if [[ $_av_rn_failed -gt 0 ]]; then
        av_log_error "Real notifications: $_av_rn_failed scenario(s) failed"
        return 1
    fi

    av_log_success "Real notifications: $_av_rn_passed/$_av_rn_total passed ($_av_rn_skipped skipped)"
    return 0
}
