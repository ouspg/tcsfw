"""Command-line basic functions"""

import os
import pathlib
from typing import Dict

API_KEY_NAME = "TCSFW_SERVER_API_KEY"

def read_env_file() -> Dict[str, str]:
    """Read .env file"""
    values = {}
    env_file = pathlib.Path(".env")
    if env_file.exists():
        with env_file.open(encoding="utf-8") as f:
            for line in f:
                k, _, v = line.partition("=")
                if v is not None:
                    values[k.strip()] = v.strip()
    return values

def get_api_key() -> str:
    """Get API key from environment or .env file"""
    key = os.environ.get(API_KEY_NAME, "")
    if key:
        return key
    values = read_env_file()
    return values.get(API_KEY_NAME, "")
