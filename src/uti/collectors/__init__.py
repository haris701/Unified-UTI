"""External collector adapters."""

from uti.collectors.maigret import (
    MaigretCollector,
    MaigretCsvFindings,
    MaigretDiagnostic,
    MaigretOutputError,
    MaigretRunResult,
    parse_maigret_csv,
)
from uti.collectors.sherlock import (
    SherlockCollector,
    SherlockCsvFindings,
    SherlockRunResult,
    parse_sherlock_csv,
)

__all__ = [
    "MaigretCollector",
    "MaigretCsvFindings",
    "MaigretDiagnostic",
    "MaigretOutputError",
    "MaigretRunResult",
    "SherlockCollector",
    "SherlockCsvFindings",
    "SherlockRunResult",
    "parse_maigret_csv",
    "parse_sherlock_csv",
]
