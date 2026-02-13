#!/usr/bin/env bash
set -euo pipefail

../build/sync --scan /home/crab/crabby/dev/c/filesync --out /home/crab/crabby/dev/c/filesync/build/manifest.txt
test -f /tmp/manifest.txt
echo "OK"
