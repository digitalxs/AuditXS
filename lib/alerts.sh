#!/usr/bin/env bash
#
# AuditXS — lib/alerts.sh
# Deliver drift / vulnerability alerts to a webhook (Slack-compatible) and/or
# email, so scheduled audits actively notify instead of only failing a timer.
#
# Configure in /etc/auditxs/auditxs.conf:
#   ALERT_WEBHOOK="https://hooks.slack.com/services/…"   # or any JSON webhook
#   ALERT_EMAIL="secops@example.com"                      # needs mail/sendmail
#
#   auditxs alert status   # show configured sinks
#   auditxs alert test     # send a test alert
#

_alert_json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' '; }

# send_alert <subject> <body> — best-effort delivery to every configured sink.
# Returns 0 if at least one sink accepted it, non-zero otherwise.
send_alert() {
    local subject=$1 body=$2 host sent=0
    host=${HOSTNAME:-$(hostname 2>/dev/null)}
    if [ -z "${ALERT_WEBHOOK:-}" ] && [ -z "${ALERT_EMAIL:-}" ]; then
        ax_error AX8002; return 2
    fi
    [ -n "${ALERT_WEBHOOK:-}" ] && { _alert_webhook "$subject" "$body" "$host" && sent=1; }
    [ -n "${ALERT_EMAIL:-}" ]   && { _alert_email   "$subject" "$body" "$host" && sent=1; }
    [ "$sent" = 1 ]
}

_alert_webhook() {
    have curl || { ax_error AX8001 "sink=webhook reason=curl-not-installed"; return 1; }
    local payload
    payload=$(printf '{"text":"AuditXS [%s] — %s\n%s"}' \
        "$(_alert_json_esc "$3")" "$(_alert_json_esc "$1")" "$(_alert_json_esc "$2")")
    if curl -fsS -m 15 -X POST -H 'Content-Type: application/json' -d "$payload" "$ALERT_WEBHOOK" >/dev/null 2>&1; then
        log "[alert] webhook delivered: $1"; return 0
    fi
    ax_error AX8001 "sink=webhook url=${ALERT_WEBHOOK%%\?*}"; return 1
}

_alert_email() {
    local subj="AuditXS [$3]: $1"
    if have mail; then
        printf '%s\n' "$2" | mail -s "$subj" "$ALERT_EMAIL" 2>/dev/null && { log "[alert] email sent to $ALERT_EMAIL"; return 0; }
    elif have sendmail; then
        printf 'Subject: %s\nTo: %s\n\n%s\n' "$subj" "$ALERT_EMAIL" "$2" | sendmail -t 2>/dev/null && { log "[alert] email sent to $ALERT_EMAIL"; return 0; }
    fi
    ax_error AX8001 "sink=email to=$ALERT_EMAIL reason=no-mail-command"; return 1
}

# alerts_configured — true if any sink is set.
alerts_configured() { [ -n "${ALERT_WEBHOOK:-}" ] || [ -n "${ALERT_EMAIL:-}" ]; }

cmd_alert() {
    local sub=${1:-status}
    case $sub in
        status)
            nala_box "Alert sinks"
            if [ -n "${ALERT_WEBHOOK:-}" ]; then nala_row "Webhook: ${GREEN}configured${RC} (${ALERT_WEBHOOK%%\?*})"
            else nala_row "Webhook: ${DIM}not set (ALERT_WEBHOOK)${RC}"; fi
            if [ -n "${ALERT_EMAIL:-}" ]; then nala_row "Email:   ${GREEN}${ALERT_EMAIL}${RC}"
            else nala_row "Email:   ${DIM}not set (ALERT_EMAIL)${RC}"; fi
            nala_end
            say ""
            say "Set ${BOLD}ALERT_WEBHOOK${RC} and/or ${BOLD}ALERT_EMAIL${RC} in ${BOLD}/etc/auditxs/auditxs.conf${RC}."
            say "Alerts fire from scheduled audits on baseline drift or new CVEs. Test: ${BOLD}sudo auditxs alert test${RC}"
            ;;
        test)
            alerts_configured || { ax_error AX8002; return 1; }
            info "Sending a test alert to the configured sink(s)…"
            if send_alert "Test alert" "This is a test alert from AuditXS on $(hostname 2>/dev/null). If you can read this, alerting works."; then
                ok "Test alert delivered."
            else
                warn "Test alert could not be delivered (see the error above)."
                return 1
            fi
            ;;
        *) die "Usage: auditxs alert status | test" ;;
    esac
}
