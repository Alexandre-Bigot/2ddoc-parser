"""
Tests unitaires pour le décodage des 2D-DOC de type avis d'impôts (type 28).
"""

import os

import pytest

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.type.doca1_decision_permis_conduire import DecisionPermisConduire


@pytest.mark.skipif(
    not os.getenv("2DDOC_SAMPLE_DECISION_PERMIS_CONDUIRE"),
    reason="Ce test a besoin de la variable d'environnement 2DDOC_SAMPLE_DECISION_PERMIS_CONDUIRE",
)
class TestAvisImpots:
    """Tests pour les avis d'impôts (document type 28)."""

    @pytest.fixture
    def sample_2d_doc(self) -> str:
        """Fixture avec un 2D-DOC d'avis d'impôts réel."""
        return os.environ["2DDOC_SAMPLE_DECISION_PERMIS_CONDUIRE"]

    def test_decode_success(self, sample_2d_doc):
        """Test que le décodage réussit et retourne un résultat."""
        result = decode_2d_doc(sample_2d_doc)

        assert result is not None
        assert result.header is not None
        assert result.fields is not None
        assert result.signature is not None

    def test_header_parsing(self, sample_2d_doc):
        """Test que l'en-tête est correctement parsé."""
        result = decode_2d_doc(sample_2d_doc)
        header = result.header

        assert header.marker == "DC"
        assert header.version == 4
        assert header.doc_type == "A1"
        assert header.perimeter == "01"
        assert header.country == "FR"
        assert header.ca_id is not None
        assert header.cert_id is not None

    def test_typed_data_is_avis_imposition(self, sample_2d_doc):
        """Test que les données typées sont bien un AvisImposition."""
        result = decode_2d_doc(sample_2d_doc)

        assert result.typed is not None
        assert isinstance(result.typed, DecisionPermisConduire)
        assert result.typed.doc_type == "A1"

    def test_fields_extraction(self, sample_2d_doc):
        """Test que les champs bruts sont extraits correctement."""
        result = decode_2d_doc(sample_2d_doc)

        assert {
            "60",
            "69",
            "6A",
            "6G",
            "6H",
            "AB",
            "AC",
            "AD",
            "AE",
            "AF",
            "AG",
        }.issubset(set(result.fields))
