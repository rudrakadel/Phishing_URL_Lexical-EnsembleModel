from __future__ import annotations

import getpass

from werkzeug.security import generate_password_hash


def main() -> None:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if not password or password != confirm:
        raise SystemExit("Passwords do not match or are empty.")
    print(generate_password_hash(password))


if __name__ == "__main__":
    main()
