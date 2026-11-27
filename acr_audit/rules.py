"""Regras de checagem de labels de governança.

Entrada vinda da CLI: lista de strings no formato ``KEY`` ou ``KEY=VALUE``.
- ``KEY`` exige apenas que a label exista.
- ``KEY=VALUE`` exige que o valor bata exatamente.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LabelRequirement:
    key: str
    expected: str | None

    def is_satisfied_by(self, labels: dict[str, str]) -> bool:
        if self.key not in labels:
            return False
        if self.expected is None:
            return True
        return labels[self.key] == self.expected

    def describe_violation(self, labels: dict[str, str]) -> str:
        if self.key not in labels:
            return self.key
        return f"{self.key}!={self.expected}"


def parse_label(raw: str) -> LabelRequirement:
    """Parseia ``KEY`` ou ``KEY=VALUE``.

    O primeiro ``=`` separa chave de valor. Valor pode conter ``=``.
    Chave vazia é inválida.
    """
    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("label vazia")
    if "=" not in cleaned:
        return LabelRequirement(key=cleaned, expected=None)
    key, value = cleaned.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"chave de label vazia em: {raw!r}")
    return LabelRequirement(key=key, expected=value)


def check_labels(
    labels: dict[str, str] | None,
    required: list[LabelRequirement],
) -> list[str]:
    """Retorna a lista de violações (vazia = conforme)."""
    effective = labels or {}
    return [
        req.describe_violation(effective) for req in required if not req.is_satisfied_by(effective)
    ]
