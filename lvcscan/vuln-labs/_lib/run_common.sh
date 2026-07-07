#!/usr/bin/env bash

lvc_wait_http() {
    local port="$1"
    local path="${2:-/}"
    local timeout="${3:-240}"
    echo "[*] Waiting for http://localhost:${port}${path} ..."
    local end=$((SECONDS + timeout))
    until [ "$(curl -sk --noproxy '*' -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}${path}" 2>/dev/null || true)" != "000" ]; do
        if [ "$SECONDS" -ge "$end" ]; then
            echo "[!] timed out waiting for :${port}${path}" >&2
            return 1
        fi
        sleep 3
    done
}
