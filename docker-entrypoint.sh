#!/bin/sh
set -e

# Fix volume mount permissions
chown -R cypulse:cypulse /app/data /app/config 2>/dev/null || true

exec gosu cypulse python -m cypulse "$@"
