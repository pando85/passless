#!/bin/bash
#
# Notification daemon utilities for Tier 2 validation
# Prefers dunst + dunstctl; falls back to SKIP if unavailable.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_NOTIFICATIONS_LOADED=true

# shellcheck disable=SC2034
AV_NOTIFY_DAEMON=""
AV_NOTIFY_DAEMON_PID=""
# shellcheck disable=SC2034
AV_DBUS_SESSION_BUS_ADDRESS=""
# shellcheck disable=SC2034
AV_DISPLAY=""
AV_XVFB_PID=""

av_find_notification_daemon() {
    if command -v dunst &>/dev/null; then
        AV_NOTIFY_DAEMON="dunst"
        return 0
    fi
    return 1
}

av_find_notification_ctl() {
    if command -v dunstctl &>/dev/null; then
        return 0
    fi
    return 1
}

av_dunst_supports_actions() {
    if ! command -v dunstctl &>/dev/null; then
        return 1
    fi

    local help_output
    help_output=$(dunstctl --help 2>&1) || true

    if echo "$help_output" | grep -qi 'action'; then
        return 0
    fi

    return 1
}

av_start_xvfb() {
    if ! command -v Xvfb &>/dev/null; then
        av_log_error "Xvfb not found (required for headless display)"
        return 1
    fi

    local display_num="${1:-:99}"

    Xvfb "$display_num" -screen 0 1024x768x24 -nolisten tcp &>/dev/null &
    AV_XVFB_PID=$!

    local waited=0
    while [[ $waited -lt 5 ]]; do
        if kill -0 "$AV_XVFB_PID" 2>/dev/null; then
            AV_DISPLAY="$display_num"
            export DISPLAY="$display_num"
            return 0
        fi
        sleep 0.5
        ((waited++)) || true
    done

    av_log_error "Xvfb failed to start on display $display_num"
    AV_XVFB_PID=""
    return 1
}

av_stop_xvfb() {
    if [[ -n "${AV_XVFB_PID:-}" ]] && kill -0 "$AV_XVFB_PID" 2>/dev/null; then
        kill "$AV_XVFB_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$AV_XVFB_PID" 2>/dev/null && [[ $waited -lt 5 ]]; do
            sleep 0.5
            ((waited++)) || true
        done
        if kill -0 "$AV_XVFB_PID" 2>/dev/null; then
            kill -9 "$AV_XVFB_PID" 2>/dev/null || true
        fi
    fi
    AV_XVFB_PID=""
    # shellcheck disable=SC2034 # consumed by stage scripts after sourcing
    AV_DISPLAY=""
}

av_start_dbus_session() {
    if ! command -v dbus-run-session &>/dev/null; then
        av_log_error "dbus-run-session not found"
        return 1
    fi
    return 0
}

av_start_dunst() {
    if [[ "$AV_NOTIFY_DAEMON" != "dunst" ]]; then
        av_find_notification_daemon || return 1
    fi

    local config_dir="${TEMP_ROOT:-/tmp}/dunst-config-$$"
    mkdir -p "$config_dir"
    chmod 700 "$config_dir"

    local dunst_config="${config_dir}/dunstrc"
    cat > "$dunst_config" << 'DUNST_EOF'
[dunst]
follow = mouse
geometry = "300x50-10+10"
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
expire_timeout = 10
ignore_newline = no
stack_duplicates = true
hide_duplicate_count = false
show_indicators = yes
icon_position = left
max_icon_size = 32
icon_path = /usr/share/icons/gnome/16x16/status/:/usr/share/icons/gnome/16x16/devices/
sticky_history = yes
history_length = 20
title = Dunst
class = notification
startup_notification = false
verbosity = mesg
corner_radius = 0
mouse_left_click = do_action
mouse_middle_click = close_all
mouse_right_click = close_current

[experimental]
per_monitor_dpi = false

[shortcuts]

[urgency_low]
background = "#222222"
foreground = "#888888"
timeout = 10

[urgency_normal]
background = "#1c1f22"
foreground = "#ffffff"
timeout = 10

[urgency_critical]
background = "#900000"
foreground = "#ffffff"
frame_color = "#ff0000"
timeout = 0
DUNST_EOF

    dunst -config "$dunst_config" &>/dev/null &
    AV_NOTIFY_DAEMON_PID=$!

    local waited=0
    while [[ $waited -lt 5 ]]; do
        if dunstctl running 2>/dev/null | grep -qi 'true\|running\|1'; then
            return 0
        fi
        if command -v notify-send &>/dev/null; then
            notify-send "test" "test" 2>/dev/null && {
                sleep 0.5
                local notifications
                notifications=$(dunstctl count 2>/dev/null || echo "0")
                if [[ "$notifications" != "0" ]] && [[ -n "$notifications" ]]; then
                    return 0
                fi
            }
        fi
        sleep 0.5
        ((waited++)) || true
    done

    if kill -0 "$AV_NOTIFY_DAEMON_PID" 2>/dev/null; then
        return 0
    fi

    av_log_error "dunst failed to start"
    AV_NOTIFY_DAEMON_PID=""
    return 1
}

av_stop_dunst() {
    if [[ -n "${AV_NOTIFY_DAEMON_PID:-}" ]] && kill -0 "$AV_NOTIFY_DAEMON_PID" 2>/dev/null; then
        kill "$AV_NOTIFY_DAEMON_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$AV_NOTIFY_DAEMON_PID" 2>/dev/null && [[ $waited -lt 5 ]]; do
            sleep 0.5
            ((waited++)) || true
        done
        if kill -0 "$AV_NOTIFY_DAEMON_PID" 2>/dev/null; then
            kill -9 "$AV_NOTIFY_DAEMON_PID" 2>/dev/null || true
        fi
    fi
    AV_NOTIFY_DAEMON_PID=""
}

av_stop_notification_stack() {
    av_stop_dunst
    av_stop_xvfb
}

av_send_notification() {
    local summary="$1"
    local body="${2:-}"
    local urgency="${3:-normal}"
    local actions="${4:-}"

    if ! command -v notify-send &>/dev/null; then
        av_log_error "notify-send not found"
        return 1
    fi

    local cmd=(notify-send)
    cmd+=("--urgency=$urgency")

    if [[ -n "$body" ]]; then
        cmd+=("$summary" "$body")
    else
        cmd+=("$summary")
    fi

    if [[ -n "$actions" ]]; then
        IFS=',' read -ra action_pairs <<< "$actions"
        for pair in "${action_pairs[@]}"; do
            local key="${pair%%=*}"
            local label="${pair#*=}"
            cmd+=("--action=${key}=${label}")
        done
    fi

    "${cmd[@]}" 2>/dev/null
}

av_dunstctl_action() {
    local action_index="${1:-0}"

    if ! command -v dunstctl &>/dev/null; then
        av_log_error "dunstctl not found"
        return 1
    fi

    dunstctl action "$action_index" 2>/dev/null
}

av_dunstctl_close() {
    if ! command -v dunstctl &>/dev/null; then
        av_log_error "dunstctl not found"
        return 1
    fi

    dunstctl close 2>/dev/null
}

av_dunstctl_close_all() {
    if ! command -v dunstctl &>/dev/null; then
        av_log_error "dunstctl not found"
        return 1
    fi

    dunstctl close-all 2>/dev/null
}

av_dunstctl_count() {
    if ! command -v dunstctl &>/dev/null; then
        echo "0"
        return 0
    fi

    dunstctl count 2>/dev/null || echo "0"
}

av_notification_prereqs_check() {
    if ! av_find_notification_daemon; then
        av_log_error "No notification daemon found (dunst required)"
        return 1
    fi

    if ! av_find_notification_ctl; then
        av_log_error "dunstctl not found (required for action/dismiss control)"
        return 1
    fi

    if ! command -v Xvfb &>/dev/null; then
        av_log_error "Xvfb not found (required for headless display)"
        return 1
    fi

    if ! command -v dbus-run-session &>/dev/null; then
        av_log_error "dbus-run-session not found"
        return 1
    fi

    if ! command -v notify-send &>/dev/null; then
        av_log_error "notify-send not found"
        return 1
    fi

    return 0
}

av_probe_binary() {
    local search_paths=(
        "${PASSLESS_PROMPT_PROBE_BIN:-}"
        "${CARGO_TARGET_DIR:-target}/release/agent-prompt-probe"
        "${CARGO_TARGET_DIR:-target}/debug/agent-prompt-probe"
    )
    for p in "${search_paths[@]}"; do
        if [[ -n "$p" ]] && [[ -x "$p" ]]; then
            printf '%s' "$p"
            return 0
        fi
    done
    return 1
}

av_wait_for_notification() {
    local timeout_secs="${1:-10}"
    local poll_interval="${2:-0.2}"
    local deadline
    deadline=$(($(date +%s%N) + timeout_secs * 1000000000))

    while [[ $(date +%s%N) -lt $deadline ]]; do
        local count
        count=$(dunstctl count 2>/dev/null || echo "0")
        if [[ "$count" =~ ^[0-9]+$ ]] && [[ "$count" -gt 0 ]]; then
            return 0
        fi
        sleep "$poll_interval"
    done
    return 1
}

av_wait_for_dunst_history_contains() {
    local pattern="${1:-Passless}"
    local timeout_secs="${2:-10}"
    local poll_interval="${3:-0.2}"
    local deadline
    deadline=$(($(date +%s%N) + timeout_secs * 1000000000))

    while [[ $(date +%s%N) -lt $deadline ]]; do
        if dunstctl history 2>/dev/null | grep -q "$pattern"; then
            return 0
        fi
        sleep "$poll_interval"
    done
    return 1
}

av_dunstctl_history() {
    dunstctl history 2>/dev/null || echo ""
}

av_next_xvfb_display() {
    local base="${AV_XVFB_DISPLAY_BASE:-100}"
    local max="${AV_XVFB_DISPLAY_MAX:-199}"
    local d=$base
    while [[ $d -le $max ]]; do
        if [[ ! -e "/tmp/.X${d}-lock" ]]; then
            printf ':%d' "$d"
            return 0
        fi
        ((d++)) || true
    done
    return 1
}
