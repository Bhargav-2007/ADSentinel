"""Structured logging excludes arbitrary protocol exceptions and credential fields."""

import json
import logging
from datetime import datetime, timezone


class SafeFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "event": record.getMessage(),
            }
        )


def get_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("adsentinel")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(SafeFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.propagate = False
    return logger
