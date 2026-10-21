#!/usr/bin/env bash
# Explicit external own-systems component; no full WPScan install/redistribution.
set -euo pipefail
python RedJohn/scripts/install-wpscan-observe.py \
  --cache "$RUNNER_TEMP/wordpress-cache" \
  --destination "$PWD/RedJohn/.tools/wordpress-observe/4.1.0" \
  --logs "$PWD/artifacts/wordpress-build" --external-operator-component
cp RedJohn/.tools/wordpress-observe/4.1.0/receipt.json artifacts/tool-receipts/wordpress-observe.json
cp RedJohn/.tools/wordpress-observe/4.1.0/runtime-manifest.json artifacts/wordpress-runtime-manifest.json
