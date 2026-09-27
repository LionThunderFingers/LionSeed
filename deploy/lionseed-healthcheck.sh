#!/usr/bin/env bash
# Dead man's switch: ping PING_URL only when the seed is healthy, so silence raises the alarm.
# Never restarts or repairs anything; a monitor that fixes things hides the problem.
#
# Environment (from /etc/default/lionseed-healthcheck): PING_URL, SEED_HOST, BIND_IP,
# optional DUMP (default /var/lib/lionseed/lionseed.dump) and MAX_DUMP_AGE (default 3600 s).

set -uo pipefail
DUMP="${DUMP:-/var/lib/lionseed/lionseed.dump}"
MAX_DUMP_AGE="${MAX_DUMP_AGE:-3600}"
problems=()

systemctl is-active --quiet lionseed || problems+=("lionseed service is not active")

if [ -f "$DUMP" ]; then
    age=$(( $(date +%s) - $(stat -c %Y "$DUMP") ))
    [ "$age" -le "$MAX_DUMP_AGE" ] || problems+=("dump is ${age}s old (limit ${MAX_DUMP_AGE}s)")
    good=$(awk 'NR>1 && $2==1' "$DUMP" | wc -l)
    [ "$good" -gt 0 ] || problems+=("no good nodes in the dump")
else
    problems+=("no dump at $DUMP")
fi

answers=$(dig "@${BIND_IP}" "$SEED_HOST" A +short +time=5 +tries=2 2>/dev/null | grep -cE '^[0-9.]+$')
[ "${answers:-0}" -gt 0 ] || problems+=("DNS returned no A records for $SEED_HOST")

if [ "${#problems[@]}" -eq 0 ]; then
    curl -fsS -m 10 --retry 3 "$PING_URL" >/dev/null
else
    printf 'unhealthy:\n' >&2
    printf '  - %s\n' "${problems[@]}" >&2
    # Report the failure explicitly where the service supports it (healthchecks.io /fail).
    curl -fsS -m 10 "${PING_URL%/}/fail" --data-raw "$(printf '%s\n' "${problems[@]}")" >/dev/null 2>&1 || true
    exit 1
fi
