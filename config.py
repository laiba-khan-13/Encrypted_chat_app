"""
Configuration module for the Encrypted Chat Application.
Centralized settings for server, client, and encryption.
"""

import os
from pathlib import Path


# Base Paths
BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Network Settings
HOST = os.getenv("CHAT_HOST", "127.0.0.1")
PORT = int(os.getenv("CHAT_PORT", "5555"))
MAX_CONNECTIONS = int(os.getenv("CHAT_MAX_CONN", "50"))
BUFFER_SIZE = 4096

# Encryption Settings
KEY_FILE = BASE_DIR / "secret.key"
KEY_ENCODING = "utf-8"

# Application Settings
APP_NAME = "SecureChat"
VERSION = "1.0.0"
MAX_USERNAME_LEN = 20
MAX_MESSAGE_LEN = 2000


class Colors:
    """Disabled colors for Windows Command Prompt compatibility."""
    HEADER = ""
    BLUE = ""
    CYAN = ""
    GREEN = ""
    YELLOW = ""
    RED = ""
    MAGENTA = ""
    BOLD = ""
    UNDERLINE = ""
    END = ""
    DIM = ""