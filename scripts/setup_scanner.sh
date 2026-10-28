#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -m)" in
    arm64|aarch64) docker_arch=arm64 ;;
    x86_64|amd64) docker_arch=amd64 ;;
    *) echo "Unsupported host architecture: $(uname -m)" >&2; exit 2 ;;
esac

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/pyproject.toml" | head -1)
docker build --platform "linux/$docker_arch" \
    --tag "aegis-scanner:$version" --file "$root/Dockerfile.scanner" "$root"
image=$(docker image inspect "aegis-scanner:$version" --format '{{index .RepoDigests 0}}')

python3 - "$root/.env.aegis" "$image" <<'PY'
import sys
from pathlib import Path

path, image = Path(sys.argv[1]), sys.argv[2]
values = {"AEGIS_SANDBOX_SCANNERS": "true", "AEGIS_SCANNER_IMAGE": image}
lines = path.read_text().splitlines() if path.exists() else []
present = set()
for index, line in enumerate(lines):
    key = line.partition("=")[0]
    if key in values:
        lines[index] = f"{key}={values[key]}"
        present.add(key)
lines.extend(f"{key}={value}" for key, value in values.items() if key not in present)
path.write_text("\n".join(lines) + "\n")
path.chmod(0o600)
PY

echo "Scanner image pinned as $image. Restart with: aegis start --no-open"
