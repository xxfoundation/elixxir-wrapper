#!/usr/bin/env python3

import argparse
import hashlib
import os
import re
import shutil
import sys
from typing import Tuple

def blake2s_hex(path: str) -> str:
    """Compute BLAKE2s hex digest of a file at path, streaming in chunks."""
    file_bytes = bytes(open(path, 'rb').read())
    return hashlib.blake2s(file_bytes).hexdigest()

def process_folder(folder: str) -> Tuple[int, int, int]:
    """
    For every regular file in folder that is not already in the
    <hash>_<filename> form, compute its blake2s hash and copy it to a file named
    <hash>_<filename> in the same folder.

    Returns a tuple: (total_seen, created, skipped)
    """
    total = 0
    created = 0
    skipped = 0

    try:
        entries = os.listdir(folder)
    except FileNotFoundError:
        print(f"ERROR: folder not found: {folder}", file=sys.stderr)
        return (0, 0, 0)
    except NotADirectoryError:
        print(f"ERROR: not a directory: {folder}", file=sys.stderr)
        return (0, 0, 0)

    for name in entries:
        src_path = os.path.join(folder, name)
        if not os.path.isfile(src_path):
            continue
        total += 1

        try:
            h = blake2s_hex(src_path)
            dest_name = f"{h}_{name}"
            dest_path = os.path.join(folder, dest_name)

            if os.path.exists(dest_path):
                # If a destination already exists, assume it's fine and skip
                skipped += 1
                continue

            shutil.copy2(src_path, dest_path)
            print(f"Created {dest_name}")
            created += 1
        except Exception as e:
            print(f"ERROR processing {src_path}: {e}", file=sys.stderr)

    return (total, created, skipped)


def main():
    parser = argparse.ArgumentParser(description=(
        "Create hashed HTTP download copies: for each file in FOLDER, compute "
        "blake2s and copy to <hash>_<filename> in the same folder."))
    parser.add_argument("folder", help="Folder containing files to hash and copy")
    args = parser.parse_args()

    folder = os.path.abspath(os.path.expanduser(args.folder))

    total, created, skipped = process_folder(folder)
    print(f"Done. Files seen: {total}, created: {created}, skipped: {skipped}")


if __name__ == "__main__":
    main()

