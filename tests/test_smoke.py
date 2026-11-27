"""Smoke test: garante que o pacote importa e o pytest está operacional."""

from __future__ import annotations

import acr_audit


def test_package_imports() -> None:
    assert acr_audit.__version__
