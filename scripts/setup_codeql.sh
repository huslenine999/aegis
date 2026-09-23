#!/bin/sh
set -eu

version=2.27.0
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime="$root/.aegis/codeql-runtime"
case "$(uname -m)" in
    arm64|aarch64)
        platform=linux-arm64
        docker_arch=arm64
        checksum=06ce6cf3546abe5f71af83ac98eea3da23eae528b7eeb1a1e61eeed0868817e2
        ;;
    x86_64|amd64)
        platform=linux64
        docker_arch=amd64
        checksum=8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305
        ;;
    *) echo "Unsupported host architecture: $(uname -m)" >&2; exit 2 ;;
esac

archive="$runtime/codeql-bundle-$platform.tar.gz"
mkdir -p "$runtime"
curl --fail --location --retry 3 --output "$archive" \
    "https://github.com/github/codeql-action/releases/download/codeql-bundle-v$version/codeql-bundle-$platform.tar.gz"
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 -c -
rm -rf "$runtime/codeql"
tar -xzf "$archive" -C "$runtime"
docker build --platform "linux/$docker_arch" \
    --tag "aegis-codeql:$version" --file "$root/Dockerfile.codeql" "$runtime"
image=$(docker image inspect "aegis-codeql:$version" --format '{{index .RepoDigests 0}}')

python3 - "$root/.env.aegis" "$image" <<'PY'
import sys
from pathlib import Path

path, image = Path(sys.argv[1]), sys.argv[2]
values = {
    "AEGIS_ALLOW_DEEP_SCANS": "true",
    "AEGIS_ISOLATED_WORKER": "true",
    "AEGIS_CODEQL_IMAGE": image,
    "AEGIS_CODEQL_PYTHON_SUITE": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "AEGIS_CODEQL_JAVASCRIPT_SUITE": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
}
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

echo "CodeQL $version is pinned as $image. Restart with: aegis start --no-open"
