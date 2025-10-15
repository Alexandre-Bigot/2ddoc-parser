from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional, Any

from fr_2ddoc_parser.model.models import Decoded2DDoc

# Définition d'un 'type handler' : transforme un Decoded2DDoc -> objet typé
TypeHandler = Callable[[Decoded2DDoc], Any]


@dataclass
class TypeInfo:
    code: str
    handler: TypeHandler


class TypeRegistry:
    def __init__(self):
        self._handlers: Dict[str, TypeHandler] = {}

    def register(self, code: str, handler: TypeHandler):
        self._handlers[code.upper()] = handler

    def get(self, code: str) -> Optional[TypeHandler]:
        return self._handlers.get(code.upper())


# Registre global simple
_registry = TypeRegistry()


def register(code: str):
    def deco(fn: TypeHandler):
        _registry.register(code, fn)
        return fn

    return deco


def get_handler(code: str) -> Optional[TypeHandler]:
    return _registry.get(code)
