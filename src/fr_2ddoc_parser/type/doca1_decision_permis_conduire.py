from __future__ import annotations

from datetime import date
from typing import Dict, Literal

from pydantic import BaseModel, Field

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import to_date_ddmmyyyy, to_int
from fr_2ddoc_parser.registry.registry import register


class DecisionPermisConduire(BaseModel):
    """
    Modèle typé pour une Décision Ministère de l'Interieur relative à un permis de conduire(A1).
    """

    doc_type: Literal["A1"]
    prenom: str  # 60
    date_naissance: date  # 69
    nom_de_famille: str  # 6G
    civilite: Literal["MONSIEUR", "MADAME"]  # 6H
    reference_document: str = Field(examples=["48SI"])  # AB
    numero_permis_conduire: str  # AC
    commune_naissance: str  # 6A
    champ_mystère: str  # AD
    quatre_derniers_chiffres_lettre: str  # AE
    nombre_points_perdus: int = Field(
        ...,
        description="Dans le cas d'une 48SI, nombre de points perdus lors de l'infraction ayant entrainée la 48SI",
        examples=[3],
    )  # AF
    nombre_points_permis_conduire: int = Field(
        ..., description="Nombre de points sur le permis de conduire", examples=[0]
    )  # AG

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    # -------------------------
    # Construction depuis Decoded2DDoc
    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "DecisionPermisConduire":
        f = d.fields
        known = {"60", "69", "6A", "6G", "6H", "AB", "AC", "AD", "AE", "AF", "AG"}

        extras = {k: v for k, v in f.items() if k not in known}

        obj = cls(
            doc_type=d.header.doc_type,
            prenom=f.get("60"),
            date_naissance=to_date_ddmmyyyy(f.get("69")),
            nom_de_famille=f.get("6G"),
            civilite=f.get("6H"),
            reference_document=f.get("AB"),
            numero_permis_conduire=f.get("AC"),
            commune_naissance=f.get("6A"),
            champ_mystère=f.get("AD"),
            quatre_derniers_chiffres_lettre=f.get("AE"),
            nombre_points_perdus=to_int(f.get("AF")),
            nombre_points_permis_conduire=to_int(f.get("AG")),
            extras=extras,
        )
        # Ne pas utiliser la validation Pydantic pour les règles métier :
        # on conserve le comportement existant en appelant validate() explicitement.
        obj.validate()
        return obj

    # -------------------------
    # Validation des règles O / F + O(1)/O(2)
    def validate(self) -> None:
        pass


# -----------------------------
# Handlers d’enregistrement
@register("A1", "decision_permis_conduire")
def _handle_a1(doc: Decoded2DDoc) -> DecisionPermisConduire:
    return DecisionPermisConduire.from_decoded(doc)
