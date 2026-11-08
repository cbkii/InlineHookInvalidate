#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
${CXX:-c++} -std=c++17 -Wall -Wextra -Werror -pthread \
    -Itests/stubs tests/lifecycle.cpp -o "$build/lifecycle"
# The lifecycle test exercises config files that must be owned by UID 0.
if [ "$(id -u)" = 0 ]; then
    "$build/lifecycle"
else
    sudo "$build/lifecycle"
fi
sh -n module/template/customize.sh
node --check module/template/webroot/app.js
diff -r module/template/webroot webui-app/src/main/assets/webroot
