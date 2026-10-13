#!/usr/bin/env python3
"""Inventory Linux file-capability xattrs without relying on getcap."""

import errno
import os
import sys


CAPABILITY_XATTR = "security.capability"
IGNORED_XATTR_ERRORS = {
    errno.ENODATA,
    errno.ENOTSUP,
    getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
}


def record_context() -> None:
    with open("/proc/self/status", encoding="utf-8") as status_file:
        for line in status_file:
            if line.startswith(("Uid:", "Gid:", "CapEff:", "NoNewPrivs:")):
                print(line.rstrip(), file=sys.stderr)


def main() -> int:
    record_context()
    root_device = os.lstat("/").st_dev

    for current, directories, files in os.walk("/", topdown=True, followlinks=False):
        retained_directories = []
        for name in directories:
            path = os.path.join(current, name)
            try:
                if os.lstat(path).st_dev == root_device:
                    retained_directories.append(name)
            except OSError as error:
                print(f"walk_error path={path} errno={error.errno}", file=sys.stderr)
        directories[:] = retained_directories

        for name in files:
            path = os.path.join(current, name)
            try:
                if os.lstat(path).st_dev != root_device:
                    continue
                value = os.getxattr(path, CAPABILITY_XATTR, follow_symlinks=False)
            except OSError as error:
                if error.errno not in IGNORED_XATTR_ERRORS:
                    print(f"xattr_error path={path} errno={error.errno}", file=sys.stderr)
                continue
            print(f"path={path} security.capability={value.hex()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
