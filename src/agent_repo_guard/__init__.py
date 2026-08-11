"""Public package interface for agent-repo-guard."""

from .models import Finding, Severity
from .scanner import ScanOptions, scan_paths

__all__ = ["Finding", "ScanOptions", "Severity", "scan_paths"]
__version__ = "0.1.0"
