#!/bin/sh
# Keep the direct shell entry point aligned with the cross-platform npm builder.
set -eu
cd "$(dirname "$0")/.."
npm run build:mcpb
