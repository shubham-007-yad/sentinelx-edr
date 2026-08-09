import os
import sys

agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

try:
    from file_metadata import FileMetadataCollector, collect_file_metadata, get_file_metadata_json
except ImportError:
    FileMetadataCollector = None
    collect_file_metadata = None
    get_file_metadata_json = None

__all__ = [
    "FileMetadataCollector",
    "collect_file_metadata",
    "get_file_metadata_json",
]
