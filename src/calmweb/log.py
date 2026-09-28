"""Logging utilities for CalmWeb."""
from __future__ import annotations
import contextlib
import sys
import threading
import time
from collections import deque
from typing import Any

# Buffer partagé
log_buffer: deque[str] = deque(maxlen=1000)
# Lock partagé pour éviter les crashs de lecture/écriture simultanée
_LOG_LOCK = threading.Lock()

def log(msg: Any) -> None:
    """Thread-safe log to console and in-memory buffer with duplicate suppression."""
    try:
        timestamp = time.strftime("[%H:%M:%S]")
        try:
            safe_msg = str(msg).encode("utf-8", errors="replace").decode("utf-8", errors="replace")
        except Exception:
            safe_msg = "Log message conversion error"

        line = f"{timestamp} {safe_msg}"

        with _LOG_LOCK:
            # Check if buffer is not empty and compare the message content
            # We strip the timestamp [HH:MM:SS] from the last line to compare only the message
            if log_buffer:
                last_line = log_buffer[-1]
                # last_line[11:] removes the "[HH:MM:SS] " prefix (11 characters)
                if last_line[11:] == safe_msg:
                    return

            log_buffer.append(line)
            
            with contextlib.suppress(Exception):
                print(line, flush=True)

    except Exception:
        with contextlib.suppress(Exception):
            sys.stderr.write("Logging internal error\n")