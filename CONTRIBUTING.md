# Guide de contribution

Merci de votre intérêt pour contribuer à **2ddoc-parser** ! 🎉

Ce guide vous explique comment ajouter le support d'un nouveau type de document 2D-DOC.

## 📋 Table des matières

- [Ajouter un nouveau type de document](#ajouter-un-nouveau-type-de-document)
- [Structure d'un handler de type](#structure-dun-handler-de-type)
- [Étapes détaillées](#étapes-détaillées)
- [Tests](#tests)
- [Bonnes pratiques](#bonnes-pratiques)

## 🆕 Ajouter un nouveau type de document

Pour ajouter le support d'un nouveau type de document 2D-DOC (par exemple, un permis de conduire, une carte grise, etc.), suivez ces étapes :

### Vue d'ensemble

1. Créer un nouveau fichier dans `src/fr_2ddoc_parser/type/`
2. Définir les modèles de données (dataclasses)
3. Implémenter la méthode `from_decoded()`
4. Implémenter la méthode `validate()`
5. Enregistrer le handler avec le décorateur `@register()`
6. Ajouter des tests unitaires

## 📚 Structure d'un handler de type

Prenons comme exemple le fichier `doc28_avis_impots.py` qui gère les avis d'impôts (type 28).

### 1. Imports nécessaires

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, date
from decimal import Decimal
from typing import Optional, Dict, Literal

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import to_int, to_dec, to_date_ddmmyyyy
from fr_2ddoc_parser.registry.registry import register
```

### 2. Définir les modèles de données

Créez des dataclasses pour représenter la structure du document :

```python
@dataclass
class MonDocument:
    """Modèle typé pour [Description du document] (type XX)."""
    doc_type: Literal["XX"]  # Remplacez XX par le code du type
    
    # Champs obligatoires (sans valeur par défaut)
    champ_obligatoire_1: str                    # ID_CHAMP (O)
    champ_obligatoire_2: int                    # ID_CHAMP (O)
    
    # Champs facultatifs (avec Optional et valeur par défaut)
    champ_facultatif_1: Optional[str] = None    # ID_CHAMP (F)
    champ_facultatif_2: Optional[date] = None   # ID_CHAMP (F)
    
    # Champs supplémentaires non mappés
    extras: Dict[str, str] = field(default_factory=dict)
```

**Conventions de nommage :**
- Utilisez `snake_case` pour les noms de champs
- Ajoutez des commentaires avec l'ID du champ et (O) pour obligatoire, (F) pour facultatif
- Utilisez les types appropriés : `str`, `int`, `Decimal`, `date`, etc.

### 3. Implémenter `from_decoded()`

Cette méthode construit l'objet typé à partir du `Decoded2DDoc` parsé :

```python
@classmethod
def from_decoded(cls, d: Decoded2DDoc) -> "MonDocument":
    f = d.fields  # Raccourci pour accéder aux champs
    
    # Liste des IDs de champs connus
    known = {
        "ID1", "ID2", "ID3", "ID4", ...
    }
    
    # Récupérer les champs extras (non mappés)
    extras = {k: v for k, v in f.items() if k not in known}
    
    # Construire l'objet
    obj = cls(
        doc_type=d.header.doc_type,
        champ_obligatoire_1=f.get("ID1", "").strip(),
        champ_obligatoire_2=_to_int(f.get("ID2")),
        champ_facultatif_1=f.get("ID3"),
        champ_facultatif_2=_to_date_ddmmyyyy(f.get("ID4")),
        extras=extras,
    )
    
    # Valider avant de retourner
    obj.validate()
    return obj
```

**Fonctions d'aide disponibles** (dans `parser.helper`) :
- `_to_int(s)` : Convertit une chaîne en `int` (gère les espaces, points, virgules)
- `_to_dec(s)` : Convertit une chaîne en `Decimal`
- `_to_date_ddmmyyyy(s)` : Convertit une date `DDMMYYYY` en objet `date`

### 4. Implémenter `validate()`

Cette méthode vérifie que les champs obligatoires sont présents et valides :

```python
def validate(self) -> None:
    """Valide les champs obligatoires et les règles métier."""
    if not self.champ_obligatoire_1:
        raise ValueError("Le champ_obligatoire_1 (ID1) est obligatoire.")
    if not self.champ_obligatoire_2:
        raise ValueError("Le champ_obligatoire_2 (ID2) est obligatoire.")
    
    # Règles métier supplémentaires
    if self.champ_obligatoire_2 < 0:
        raise ValueError("Le champ_obligatoire_2 doit être positif.")
```

### 5. Enregistrer le handler

Utilisez le décorateur `@register()` pour enregistrer automatiquement le handler :

```python
@register("XX")  # Remplacez XX par le code du type
def _handle_XX(doc: Decoded2DDoc) -> MonDocument:
    """Handler pour le type XX."""
    return MonDocument.from_decoded(doc)
```

**Important :** Le décorateur s'exécute automatiquement lors de l'import du module.

## 🔧 Étapes détaillées

### Exemple complet : Ajouter le support d'un permis de conduire (type hypothétique "42")

#### 1. Créer le fichier

Créez `src/fr_2ddoc_parser/type/doc42_permis_conduire.py`

#### 2. Écrire le code complet

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from typing import Optional, Dict, Literal

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import to_date_ddmmyyyy
from fr_2ddoc_parser.registry.registry import register


@dataclass
class PermisConduire:
    """Modèle typé pour Permis de conduire (type 42)."""
    doc_type: Literal["42"]

    # Champs obligatoires
    nom: str  # 4A (O)
    prenom: str  # 4B (O)
    date_naissance: date  # 4C (O)
    numero_permis: str  # 4D (O)

    # Champs facultatifs
    date_delivrance: Optional[date] = None  # 4E (F)
    categories: Optional[str] = None  # 4F (F)

    extras: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "PermisConduire":
        f = d.fields
        known = {"4A", "4B", "4C", "4D", "4E", "4F"}
        extras = {k: v for k, v in f.items() if k not in known}

        obj = cls(
            doc_type=d.header.doc_type,
            nom=f.get("4A", "").strip(),
            prenom=f.get("4B", "").strip(),
            date_naissance=to_date_ddmmyyyy(f.get("4C")),
            numero_permis=f.get("4D", "").strip(),
            date_delivrance=to_date_ddmmyyyy(f.get("4E")),
            categories=f.get("4F"),
            extras=extras,
        )
        obj.validate()
        return obj

    def validate(self) -> None:
        """Valide les champs obligatoires."""
        if not self.nom:
            raise ValueError("Nom (4A) est obligatoire.")
        if not self.prenom:
            raise ValueError("Prénom (4B) est obligatoire.")
        if not self.date_naissance:
            raise ValueError("Date de naissance (4C) est obligatoire.")
        if not self.numero_permis:
            raise ValueError("Numéro de permis (4D) est obligatoire.")


@register("42")
def _handle_42(doc: Decoded2DDoc) -> PermisConduire:
    """Handler pour le permis de conduire (type 42)."""
    return PermisConduire.from_decoded(doc)
```

#### 3. Le module sera chargé automatiquement

Le système de chargement dynamique dans `api.py` importera automatiquement votre module lors du premier appel à `decode_2d_doc()`.

## ✅ Tests

### Créer un fichier de tests

Créez `tests/test_permis_conduire.py` :

```python
import pytest
from datetime import date

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.type.doc42_permis_conduire import PermisConduire


class TestPermisConduire:
    """Tests pour les permis de conduire (type 42)."""

    @pytest.fixture
    def sample_2d_doc(self):
        """Fixture avec un 2D-DOC de permis de conduire."""
        return "DC04FR01ABCD12345678420142DOE4BJOHN4C15081990...US[signature]"

    def test_decode_success(self, sample_2d_doc):
        """Test que le décodage réussit."""
        result = decode_2d_doc(sample_2d_doc)
        
        assert result is not None
        assert result.typed is not None
        assert isinstance(result.typed, PermisConduire)

    def test_permis_mandatory_fields(self, sample_2d_doc):
        """Test que tous les champs obligatoires sont présents."""
        result = decode_2d_doc(sample_2d_doc)
        permis = result.typed
        
        assert permis.nom == "DOE"
        assert permis.prenom == "JOHN"
        assert permis.date_naissance == date(1990, 8, 15)
        assert permis.numero_permis is not None

    def test_invalid_data_raises_error(self):
        """Test qu'un document invalide lève une erreur."""
        # Document sans nom
        invalid = "DC04FR01ABCD12345678420144BJOHN4C15081990..."
        
        with pytest.raises(ValueError, match="Nom .* obligatoire"):
            decode_2d_doc(invalid)
```

### Lancer les tests

```bash
poetry run pytest tests/test_permis_conduire.py -v
```

## 📝 Bonnes pratiques

### 1. Documentation

- Documentez chaque champ avec son ID et son caractère obligatoire/facultatif
- Ajoutez des docstrings aux classes et méthodes
- Mettez à jour le README.md pour lister le nouveau type

### 2. Validation stricte

- Validez tous les champs obligatoires dans `validate()`
- Levez des `ValueError` avec des messages clairs
- Vérifiez les règles métier (formats, plages de valeurs, etc.)

### 3. Typage

- Utilisez `Literal` pour le `doc_type`
- Utilisez `Optional` pour les champs facultatifs
- Préférez les types natifs Python (`date`, `Decimal`) aux chaînes

### 4. Gestion des champs inconnus

- Stockez les champs non mappés dans `extras`
- Cela permet de ne pas perdre d'information

### 5. Tests complets

- Testez le cas nominal (document valide)
- Testez les cas d'erreur (champs manquants, formats invalides)
- Testez les champs facultatifs présents et absents
- Testez la validation

## 🐛 Corriger un bug

1. **Fork** le projet
2. Créez une **branche** : `git checkout -b fix/mon-bug`
3. **Corrigez** le bug
4. Ajoutez un **test** qui reproduit le bug
5. **Committez** : `git commit -m "fix: description du bug corrigé"`
6. **Push** : `git push origin fix/mon-bug`
7. Créez une **Pull Request**

## 📖 Améliorer la documentation

Les améliorations de documentation sont toujours les bienvenues :
- Corriger des fautes de frappe
- Ajouter des exemples
- Clarifier des explications
- Traduire (si applicable)

## 🔍 Checklist avant de soumettre

- [ ] Le code suit les conventions de nommage Python (PEP 8)
- [ ] Les tests passent : `poetry run pytest`
- [ ] Le code est formaté : `poetry run ruff format`
- [ ] Pas d'erreurs de lint : `poetry run ruff check`
- [ ] La documentation est à jour (README.md si nécessaire)
- [ ] Un test unitaire couvre le nouveau code

## 💬 Questions ?

Si vous avez des questions ou besoin d'aide :
- Ouvrez une **issue** sur GitHub
- Consultez les **exemples existants** dans `src/fr_2ddoc_parser/type/`

Merci pour votre contribution ! 🙏

