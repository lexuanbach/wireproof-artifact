#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
out="${1:-runs/reproduced}"
if [ -e "$out" ]; then
  echo "Output exists. Choose a fresh directory: $out" >&2
  exit 1
fi
go test -race ./...
go vet ./...
python3 -m unittest -v test_oracle.py
go build -o wireproof-demo .
./wireproof-demo run -out "$out" -repetitions 10
./wireproof-demo replay -dir "$out"
python3 oracle.py "$out"
./wireproof-demo summarize -dir "$out"
