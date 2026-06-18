#!/usr/bin/env bash
set -euo pipefail

while true; do
    CONTAINER_ID=$(container list --format json 2>/dev/null | jq -r 'sort_by(.configuration.creationDate) | last | .id // empty')
    if [ -n "$CONTAINER_ID" ] && [ "$CONTAINER_ID" != "null" ]; then
        break
    fi
    sleep 0.1
done

LOG_FILE="${CONTAINER_ID}.logs"
container logs -f "$CONTAINER_ID" | tee "$LOG_FILE"
