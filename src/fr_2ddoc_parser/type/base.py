from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class GenericDoc:
    """Fallback si aucun modèle dédié n'est déclaré pour doc_type."""

    doc_type: str
    perimeter: str
    country: str
    fields: Dict[str, str]
