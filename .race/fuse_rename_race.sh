#!/bin/sh
# Reproduces the fuse3-0.9 InodePathBridge rename bug that makes
# `cargo build` fail erratically under the rs-bubble hostfs FUSE mount.
#
# Run it INSIDE the sandbox, on a directory served by the FUSE mirror
# (i.e. under the rw-mapped project dir), NOT on /tmp (tmpfs) and not on
# a native filesystem:
#
#   rs-bubble run -- /path/to/fuse_rename_race.sh
#
# What it exercises (within the 1 s dentry TTL window):
#   T1: plain rename, then immediately access the moved path
#   T2: rename OVER an existing target, then immediately access the target
#   T3: rename a directory, then immediately access a file inside it
#   T4: create -> unlink -> immediately create the same name again
#
# On a correct filesystem every operation succeeds (exit 0, "OK").
# With the bridge bug, the operations fail with ENOENT ("failed with 2"),
# typically with "failures" printed for T1/T2/T3.

set -u
DIR="$(mktemp -d "${PWD}/fuse-race.XXXXXX")" || exit 1
trap 'rm -rf "$DIR"' EXIT
cd "$DIR"

fails=0; total=0
N="${1:-200}"

check() { # name cmd...
    _name=$1; shift
    total=$((total+1))
    if "$@" >/dev/null 2>&1; then :; else
        rc=$?
        # 2 = ENOENT, the signature error of the inode-map bug
        echo "FAIL[$_name]: '$*' failed with $rc (2=ENOENT)"
        fails=$((fails+1))
    fi
}

i=0
while [ $i -lt "$N" ]; do
    # T1: plain rename, immediate access to the moved dentry
    echo one > a; echo two > b
    mv -f a b
    check T1 cat b

    # T2: rename over an existing target, immediate access + write
    echo three > c
    mv -f c b
    check T2 cat b
    check T2w sh -c 'echo four > b'

    # T3: rename a directory, immediate access to a file inside it
    mkdir -p d-working; echo x > d-working/f
    mv d-working d-final
    check T3 cat d-final/f
    check T3w sh -c 'echo y > d-final/f'

    # T4: create, unlink, immediately recreate the same name
    echo z > e; rm -f e
    check T4 sh -c 'echo w > e'

    rm -f b d-final/f; rmdir d-final
    i=$((i+1))
done

if [ "$fails" -eq 0 ]; then
    echo "OK: all $total checks passed"
else
    echo "FAILED: $fails of $total checks"
    exit 1
fi
