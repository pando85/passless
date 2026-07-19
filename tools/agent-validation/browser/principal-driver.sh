#!/bin/bash

set -euo pipefail

PASSLESS_BIN="${AV_PASSLESS_BIN:?AV_PASSLESS_BIN is required}"
PROFILE_ID="${AV_PROFILE_ID:?AV_PROFILE_ID is required}"
RP_ID="${AV_RP_ID:?AV_RP_ID is required}"
FLOW="${AV_PRINCIPAL_FLOW:?AV_PRINCIPAL_FLOW is required}"
COORD_DIR="${AV_COORD_DIR:?AV_COORD_DIR is required}"
TIMEOUT_SECS="${AV_FLOW_TIMEOUT_SECS:-90}"

[[ "$PASSLESS_BIN" == /* && -x "$PASSLESS_BIN" ]] || exit 2
[[ "$COORD_DIR" == /* && -d "$COORD_DIR" && ! -L "$COORD_DIR" ]] || exit 2
[[ "$TIMEOUT_SECS" =~ ^[0-9]+$ && "$TIMEOUT_SECS" -ge 5 && "$TIMEOUT_SECS" -le 300 ]] || exit 2

agent_json() {
    "$PASSLESS_BIN" agent --profile "$PROFILE_ID" --output json "$@"
}

write_event() {
    local name="$1"
    local status="$2"
    local tmp="${COORD_DIR}/${name}.tmp.$$"
    jq -n --arg status "$status" '{status: $status}' > "$tmp"
    chmod 600 "$tmp"
    mv -f -- "$tmp" "${COORD_DIR}/${name}.json"
}

wait_terminal_intent() {
    local request_id="$1"
    agent_json intent wait "$request_id" --timeout "$TIMEOUT_SECS" --poll-interval 100
}

run_isolated() {
    local created request_id terminal state credentials credential_ref

    created=$(agent_json intent create register --rp "$RP_ID" --reason "validation registration")
    request_id=$(jq -er '.request_id' <<<"$created")
    write_event register_ready ready
    terminal=$(wait_terminal_intent "$request_id")
    state=$(jq -er '.state' <<<"$terminal")
    [[ "$state" == "approved" ]] || exit 10
    write_event register_complete approved

    credentials=$(agent_json credential list)
    credential_ref=$(jq -er --arg rp "$RP_ID" \
        '.credentials | map(select(.rp_id == $rp)) | if length == 1 then .[0].credential_ref else error("expected one RP credential") end' \
        <<<"$credentials")

    created=$(agent_json intent create authenticate --rp "$RP_ID" \
        --credential "$credential_ref" --reason "validation authentication")
    request_id=$(jq -er '.request_id' <<<"$created")
    write_event authenticate_ready ready
    terminal=$(wait_terminal_intent "$request_id")
    state=$(jq -er '.state' <<<"$terminal")
    [[ "$state" == "approved" ]] || exit 11
    write_event authenticate_complete approved

    jq -n '{flow:"isolated", registration:"approved", authentication:"approved"}'
}

browser_evaluate() {
    local expression="$1"
    local request response
    request=$(jq -cn --arg expression "$expression" \
        '{id:1,method:"Runtime.evaluate",params:{expression:$expression,awaitPromise:true,returnByValue:true}}')
    response=$(agent_json browser-control --request "$request" --timeout-ms 30000)
    jq -er '.messages | map(fromjson? // empty) | map(select(.id == 1)) | last.result.result.value' \
        <<<"$response"
}

run_delegated() {
    local session_ttl="${AV_SESSION_TTL_SECS:-30}"
    local wrong_rp="${AV_WRONG_RP_ID:-wrong.invalid}"
    local wrong_credential="0000000000000000000000000000000000000000000000000000000000000000"
    local created request_id terminal state result credentials credential_ref

    credentials=$(agent_json credential list)
    credential_ref=$(jq -er --arg rp "$RP_ID" \
        '.credentials | map(select(.rp_id == $rp)) | if length == 1 then .[0].credential_ref else error("expected one RP credential") end' \
        <<<"$credentials")

    if agent_json delegation request --rp "$wrong_rp" --credential "$credential_ref" \
        --session-ttl "$session_ttl" --reason "negative RP check" >/dev/null 2>&1; then
        exit 20
    fi
    write_event wrong_rp_denied denied

    if agent_json delegation request --rp "$RP_ID" --credential "$wrong_credential" \
        --session-ttl "$session_ttl" --reason "negative credential check" >/dev/null 2>&1; then
        exit 21
    fi
    write_event wrong_credential_denied denied

    created=$(agent_json delegation request --rp "$RP_ID" --credential "$credential_ref" \
        --session-ttl "$session_ttl" --reason "validation delegation")
    request_id=$(jq -er '.request_id' <<<"$created")
    write_event delegation_ready ready
    terminal=$(agent_json delegation wait "$request_id" --timeout "$TIMEOUT_SECS" --poll-interval 100)
    state=$(jq -er '.state' <<<"$terminal")
    [[ "$state" == "approved" ]] || exit 22
    write_event delegation_approved approved

    result=$(browser_evaluate '(async()=>{const l=document.getElementById("log");const b=(l.innerText.match(/AUTH OK/g)||[]).length;document.getElementById("btnAuthenticate").click();for(let i=0;i<300;i++){await new Promise(r=>setTimeout(r,100));const t=l.innerText;if((t.match(/AUTH OK/g)||[]).length>b)return "auth_ok";if(t.includes("AUTH FAIL")||t.includes("Authentication error"))return "auth_failed";}return "timeout";})()')
    [[ "$result" == "auth_ok" ]] || exit 23
    write_event delegated_authentication approved

    result=$(browser_evaluate '(async()=>{const l=document.getElementById("log");const b=(l.innerText.match(/AUTH FAIL|Authentication error/g)||[]).length;document.getElementById("btnAuthenticate").click();for(let i=0;i<300;i++){await new Promise(r=>setTimeout(r,100));const n=(l.innerText.match(/AUTH FAIL|Authentication error/g)||[]).length;if(n>b)return "denied";}return "not_denied";})()')
    [[ "$result" == "denied" ]] || exit 24
    write_event second_assertion_denied denied

    jq -n '{flow:"delegated",wrong_rp:"denied",wrong_credential:"denied",authentication:"approved",second_assertion:"denied"}'
}

case "$FLOW" in
    isolated) run_isolated ;;
    delegated) run_delegated ;;
    *) exit 2 ;;
esac
