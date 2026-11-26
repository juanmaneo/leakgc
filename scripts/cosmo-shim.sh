#!/bin/sh
# Lets Cosmopolitan's toolchain run inside a container (PLAN D85).
#
# Every Cosmopolitan tool is an APE file, and an APE file starts with the bytes
# "MZ". The host registers a binfmt_misc handler for "MZ" files. That handler is
# also active in containers, where a direct exec fails with ENOENT. So each
# executable APE file is moved to NAME.real and replaced by a script that runs
# it through sh. sh reads an APE file as shell code, and the file's own header
# runs the real program.
#
# Usage: sh scripts/cosmo-shim.sh DIR
set -eu

root="${1:?usage: cosmo-shim.sh DIR}"
[ -d "$root" ] || { echo "cosmo-shim: no directory $root" >&2; exit 1; }
find "$root" -type f -perm -u+x ! -name '*.real' | while read -r f; do
    if [ "$(head -c 2 "$f")" = "MZ" ]; then
        mv "$f" "$f.real"
        printf '#!/bin/sh\nexec sh "$0.real" "$@"\n' > "$f"
        chmod +x "$f"
    fi
done
