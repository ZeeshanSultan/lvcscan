#!/usr/bin/env bash
# Wait until a lab is HTTP-ready (and optionally exploit-ready).
# Called from each lab's migrate.sh after `docker compose up`.
#
# Reads ./lab.env in the caller's directory (sourced by migrate.sh).
# Env overrides: HOST_PORT, LAB_HEALTH_PATH, LAB_HEALTH_NEEDLE, LAB_WAIT_TIMEOUT, LAB_PROBE_CMD
set -euo pipefail

HOST_PORT="${HOST_PORT:?HOST_PORT required}"
LAB_HEALTH_PATH="${LAB_HEALTH_PATH:-/}"
LAB_HEALTH_NEEDLE="${LAB_HEALTH_NEEDLE:-}"
LAB_WAIT_TIMEOUT="${LAB_WAIT_TIMEOUT:-900}"
LAB_CVE="${LAB_CVE:-}"

URL="http://localhost:${HOST_PORT}${LAB_HEALTH_PATH}"
interval=6
max=$((LAB_WAIT_TIMEOUT / interval))
label="${LAB_CVE:-lab} @ :${HOST_PORT}"

echo "[*] Waiting for ${label} — GET ${URL}"
if [ -n "$LAB_HEALTH_NEEDLE" ]; then
  echo "    needle: ${LAB_HEALTH_NEEDLE}"
fi

for ((i = 1; i <= max; i++)); do
  body=$(curl -sk --noproxy '*' -m 10 -i "$URL" 2>/dev/null || true)
  if [ -n "$LAB_HEALTH_NEEDLE" ]; then
    if grep -qiF "$LAB_HEALTH_NEEDLE" <<< "$body"; then
      ready=1
    else
      ready=0
    fi
  else
    ready=$([ -n "$body" ] && echo 1 || echo 0)
  fi

  if [ "$ready" = 1 ]; then
    if [ -n "${LAB_PROBE_CMD:-}" ]; then
      echo "[*] Running exploit-readiness probe..."
      # shellcheck disable=SC2091
      if ! ( eval "$LAB_PROBE_CMD" ); then
        echo "    probe not ready yet (${i}/${max})..."
        sleep "$interval"
        continue
      fi
    fi
    echo "[+] ${label} provisioned and ready for exploitation."
    exit 0
  fi
  if (( i % 10 == 0 )); then
    echo "    still waiting (${i}/${max})..."
  fi
  sleep "$interval"
done

echo "[!] ${label} did not become ready within ${LAB_WAIT_TIMEOUT}s" >&2
echo "    last probe: ${URL}" >&2
exit 1
