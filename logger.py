"""
Logging Module
Provides structured logging for the chat application with rotation support.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler

from config import LOGS_DIR, Colors


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to console output."""

    LEVEL_COLORS = {
        logging.DEBUG: Colors.DIM,
        logging.INFO: Colors.CYAN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, "")
        reset = Colors.END
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


def setup_logger(name: str, log_file: Path = None, level: int = logging.INFO) -> logging.Logger:
    """
    Configure a logger with both file and console handlers.

    Args:
        name: Logger name
        log_file: Optional file path for log output
        level: Logging level

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Format
    file_fmt = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    console_fmt = f"{Colors.DIM}%(asctime)s{Colors.END} | %(name)s | %(levelname)s | %(message)s"

    # File handler (rotating, max 5MB per file, keep 3 backups)
    if log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = LOGS_DIR / f"{name}_{timestamp}.log"

    file_handler = RotatingFileHandler(
        log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(file_fmt, datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter(console_fmt, datefmt="%H:%M:%S"))
    logger.addHandler(console_handler)

    return logger