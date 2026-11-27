#!/usr/bin/env bash
# Generate adapters from the exact new image before starting the service.
set -euo pipefail
BUNDLE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMAGE=${1:?Usage: prepare.sh IMAGE}
DESTINATION="$BUNDLE/generated"
mkdir -p "$DESTINATION"
STAGING=$(mktemp -d "$DESTINATION/staging.XXXXXX")
trap 'rm -rf "$STAGING"' EXIT
# Override the entry point: no application startup, database, or network access.
docker run --rm --network none --user 0 --entrypoint python3 \
  -v "$BUNDLE:/overlay:ro" -v "$STAGING:/export" "$IMAGE" -c '
import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "/overlay")
from overlay import compatibility, apply, planned_files
root = Path.cwd()
report = compatibility(root)
files = planned_files(root)
apply(root, Path("/tmp/risk-backups"))
for relative in files:
    destination = Path("/export") / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / relative, destination)
Path("/export/compatibility.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
'
# Keep the previous generated set for manual rollback, never edit user templates.
rm -rf "$DESTINATION/previous"
if [ -d "$DESTINATION/current" ]; then
  mv "$DESTINATION/current" "$DESTINATION/previous"
fi
mv "$STAGING" "$DESTINATION/current"
trap - EXIT
printf '%s\n' 'Risk overlay prepared; use docker-compose.risk-i18n.yml with the base compose file.'
