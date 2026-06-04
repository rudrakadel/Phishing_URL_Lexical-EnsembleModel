from __future__ import annotations

import os
import signal
import time


os.environ.setdefault("APP_ROLE", "worker")

from app import create_app  # noqa: E402


def main() -> None:
    create_app()
    running = True

    def stop_handler(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    while running:
        time.sleep(1)


if __name__ == "__main__":
    main()
