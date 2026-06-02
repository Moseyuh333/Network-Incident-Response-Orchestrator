"""Structured logging setup."""

from __future__ import annotations

import logging
import sys
from typing import TextIO

from app.core.config import settings


def setup_logging(
    stream: TextIO | None = None,
    level: str | None = None,
) -> logging.Logger:
    """Return a configured logger for the application."""
    log_level = getattr(logging, level or settings.log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    logger = logging.getLogger("niro")
    logger.setLevel(log_level)
    logger.addHandler(handler)
    logger.propagate = False

    return logger


log = setup_logging()
