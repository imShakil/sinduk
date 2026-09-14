import os
import logging


def get_logger(name):
    """Get a logger with the specified name."""
    LOG_PATH = os.path.expanduser("~/.config/sinduk/sinduk.log")
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if not os.access(os.path.dirname(LOG_PATH), os.W_OK):
        raise PermissionError(f"Cannot write to log file directory: {os.path.dirname(LOG_PATH)}")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(LOG_PATH)],
    )

    return logging.getLogger(name)
