"""ShieldProbe: a passive, non-exploitative web security scanner."""

__version__ = "0.1.0"

from .models import Finding, ScanResult, Severity
from .scanner import ScanError, ScopeError, TargetUnreachableError, scan

__all__ = [
    "Finding",
    "ScanError",
    "ScanResult",
    "ScopeError",
    "Severity",
    "TargetUnreachableError",
    "__version__",
    "scan",
]
