#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
exec bash ./install-and-test-auth.command --update
