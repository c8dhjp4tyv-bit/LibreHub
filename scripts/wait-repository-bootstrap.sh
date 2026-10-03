#!/bin/sh
# Include stopped containers: Compose may finish bootstrap before `up -d` returns.
set -eu

bootstrap_container=$(docker compose ps --all --quiet repository-bootstrap)
if [ -z "$bootstrap_container" ]; then
    printf '%s\n' 'Repository bootstrap container does not exist.' >&2
    exit 1
fi

# docker wait succeeds as a command even when the container itself failed.
bootstrap_status=$(timeout 120 docker wait "$bootstrap_container")
if [ "$bootstrap_status" != 0 ]; then
    printf '%s\n' 'Repository bootstrap did not complete successfully.' >&2
    exit 1
fi
