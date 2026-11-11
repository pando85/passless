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

run_isolated() {
    # The principal intent protocol (`passless agent intent ...`) was removed in ADR 0014 P7.
    # Isolated ceremonies run through the managed browser extension path, which this driver
    # does not drive, so the flow fails closed instead of reporting a result.
    echo "principal-driver: the isolated intent flow was removed (ADR 0014 P7)" >&2
    exit 3
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

run_same_user() {
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
    write_event same_user_authentication approved

    result=$(browser_evaluate '(async()=>{const l=document.getElementById("log");const b=(l.innerText.match(/AUTH OK/g)||[]).length;document.getElementById("btnAuthenticate").click();for(let i=0;i<300;i++){await new Promise(r=>setTimeout(r,100));const t=l.innerText;if((t.match(/AUTH OK/g)||[]).length>b)return "auth_ok";if(t.includes("AUTH FAIL")||t.includes("Authentication error"))return "auth_failed";}return "timeout";})()')
    [[ "$result" == "auth_ok" ]] || exit 24
    write_event second_assertion_approved approved

    jq -n '{flow:"same-user",wrong_rp:"denied",wrong_credential:"denied",authentication:"approved",second_assertion:"approved"}'
}

case "$FLOW" in
    isolated) run_isolated ;;
    same-user) run_same_user ;;
    *) exit 2 ;;
esac
