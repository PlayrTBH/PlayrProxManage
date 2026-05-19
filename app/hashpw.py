#!/usr/bin/env python3
"""
Generate a bcrypt password hash for use in proxmox-manager.env.

Usage:
    python3 -m app.hashpw            # prompts for password (hidden)
    python3 -m app.hashpw 'mypass'   # password as argument (less safe)

Copy the printed hash into BOOTSTRAP_ADMIN_PASSWORD_HASH.
"""

import getpass
import sys

import bcrypt


def main() -> None:
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm:  ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if len(password) < 8:
        print("Warning: password is shorter than 8 characters.", file=sys.stderr)
    digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    print(digest)


if __name__ == "__main__":
    main()
