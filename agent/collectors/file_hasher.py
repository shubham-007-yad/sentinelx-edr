import os
import sys

agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

try:
    from file_hasher import FileHasher, calculate_sha256
except ImportError:
    FileHasher = None
    calculate_sha256 = None

__all__ = ["FileHasher", "calculate_sha256"]
