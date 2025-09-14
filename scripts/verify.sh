#!/usr/bin/env bash
set -eux

echo "verfy.sh script running"

OUTPUT_FILE="tool_versions.txt"

> "$OUTPUT_FILE"

windeployqt6 -v >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
g++ --version >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
mingw32-make --version >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
openssl version >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
qmake6 -v >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
#npm --version >> "$OUTPUT_FILE" 2>&1
#npx --version >> "$OUTPUT_FILE" 2>&1
#/d/a/_temp/msys64/usr/bin/zip -v >> "$OUTPUT_FILE" 2>&1
