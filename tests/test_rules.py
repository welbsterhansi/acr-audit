"""Regression tests de acr_audit.rules."""

from __future__ import annotations

import pytest

from acr_audit.rules import LabelRequirement, check_labels, parse_label


class TestParseLabel:
    def test_key_only(self) -> None:
        req = parse_label("com.empresa.base-image")
        assert req == LabelRequirement(key="com.empresa.base-image", expected=None)

    def test_key_value(self) -> None:
        req = parse_label("com.empresa.pipeline=governed")
        assert req == LabelRequirement(key="com.empresa.pipeline", expected="governed")

    def test_value_may_contain_equals(self) -> None:
        req = parse_label("io.k8s.description=key=value pair, literal")
        assert req.key == "io.k8s.description"
        assert req.expected == "key=value pair, literal"

    def test_empty_value_is_allowed(self) -> None:
        req = parse_label("com.empresa.foo=")
        assert req == LabelRequirement(key="com.empresa.foo", expected="")

    def test_whitespace_is_trimmed_on_key(self) -> None:
        req = parse_label("  com.empresa.base-image  ")
        assert req.key == "com.empresa.base-image"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="vazia"):
            parse_label("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError, match="vazia"):
            parse_label("   ")

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="chave"):
            parse_label("=valor")


class TestCheckLabels:
    def test_all_present_returns_empty(self) -> None:
        required = [
            parse_label("com.empresa.base-image"),
            parse_label("com.empresa.pipeline=governed"),
        ]
        labels = {"com.empresa.base-image": "ubi9", "com.empresa.pipeline": "governed"}
        assert check_labels(labels, required) == []

    def test_missing_key_is_reported(self) -> None:
        required = [parse_label("com.empresa.base-image")]
        assert check_labels({"other": "x"}, required) == ["com.empresa.base-image"]

    def test_value_mismatch_is_reported_with_marker(self) -> None:
        required = [parse_label("com.empresa.pipeline=governed")]
        result = check_labels({"com.empresa.pipeline": "adhoc"}, required)
        assert result == ["com.empresa.pipeline!=governed"]

    def test_none_labels_report_keys_as_missing(self) -> None:
        required = [parse_label("x"), parse_label("y=z")]
        result = check_labels(None, required)
        assert result == ["x", "y"]

    def test_empty_labels_fail_everything(self) -> None:
        required = [parse_label("x")]
        assert check_labels({}, required) == ["x"]

    def test_mismatch_distinguishes_from_missing(self) -> None:
        required = [parse_label("a=1"), parse_label("b=2")]
        result = check_labels({"a": "wrong"}, required)
        assert result == ["a!=1", "b"]

    def test_key_only_matches_any_value(self) -> None:
        required = [parse_label("com.empresa.base-image")]
        assert check_labels({"com.empresa.base-image": ""}, required) == []
        assert check_labels({"com.empresa.base-image": "ubi9"}, required) == []

    def test_preserves_order_of_violations(self) -> None:
        required = [parse_label("a"), parse_label("b"), parse_label("c")]
        assert check_labels({"b": "x"}, required) == ["a", "c"]
