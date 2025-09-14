#!/usr/bin/env bash
set -eu

echo "running prepare.sh"

VERSION=$1
DESTDIR="$PWD/release/bin"
EXECUTABLE="$DESTDIR/OpenSSL-GUI.exe"
DLL_DIR="/d/a/_temp/msys64/ucrt64/bin"

qmake6
mingw32-make

echo ">>> Scanning dependencies of $EXECUTABLE"

for dll in $(ldd "$EXECUTABLE" | grep "=>" | awk '{print $3}' | grep -i '\.dll' | grep '/ucrt64/'); do
    if [ -f "$dll" ]; then
        echo "Copying $dll -> $DESTDIR"
        cp -u "$dll" "$DESTDIR/"
    fi
done
echo ">>> All dependencies copied."

windeployqt6 --release --compiler-runtime --verbose 2 "$EXECUTABLE"

cd "$DESTDIR"
/d/a/_temp/msys64/usr/bin/zip -r openssl-gui-${VERSION}.zip ./