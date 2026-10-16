"""Tests for deterministic correlation.

Events are built by ``tests.evidence_factory`` and are not BOTS v3 evidence.
"""

from __future__ import annotations

import pytest

from app.investigation.correlation import (
    CORRELATABLE_FIELDS,
    UnknownCorrelationField,
    correlate,
    distinct_values,
    field_value,
    group_by,
    group_by_dest_ip,
    group_by_host,
    group_by_src_ip,
    group_by_user,
    shared_value_groups,
)
from tests.evidence_factory import make_evidence, make_event


def test_group_by_user_collects_shared_identities() -> None:
    records = make_evidence(
        make_event(user="alpha"),
        make_event(user="beta"),
        make_event(user="alpha"),
    )

    groups = group_by_user(records)

    assert set(groups) == {"alpha", "beta"}
    assert [record.evidence_id for record in groups["alpha"]] == [
        "ev-000000",
        "ev-000002",
    ]


def test_records_without_a_value_are_omitted_not_grouped() -> None:
    records = make_evidence(
        make_event(user="alpha"),
        make_event(user=None),
        make_event(user=None),
    )

    groups = group_by_user(records)

    # Two events that both lack a user do not share a user.
    assert list(groups) == ["alpha"]
    assert None not in groups  # type: ignore[comparison-overlap]
    assert sum(len(members) for members in groups.values()) == 1


def test_blank_values_count_as_missing() -> None:
    records = make_evidence(make_event(host="   "), make_event(host="wks01"))

    assert list(group_by_host(records)) == ["wks01"]


def test_values_are_trimmed_before_grouping() -> None:
    records = make_evidence(make_event(host=" wks01 "), make_event(host="wks01"))

    groups = group_by_host(records)

    assert list(groups) == ["wks01"]
    assert len(groups["wks01"]) == 2


def test_group_keys_follow_first_occurrence() -> None:
    records = make_evidence(
        make_event(user="zulu"),
        make_event(user="alpha"),
        make_event(user="zulu"),
    )

    assert list(group_by_user(records)) == ["zulu", "alpha"]


def test_grouping_is_case_sensitive() -> None:
    # Documented limitation: identities are never case-folded, because merging
    # "Alpha" with "alpha" would be an assumption about the identity provider.
    records = make_evidence(make_event(user="Alpha"), make_event(user="alpha"))

    assert set(group_by_user(records)) == {"Alpha", "alpha"}


def test_group_by_src_and_dest_ip_are_independent() -> None:
    records = make_evidence(
        make_event(src_ip="203.0.113.25", dest_ip="10.0.1.42"),
        make_event(src_ip="10.0.1.42", dest_ip="203.0.113.25"),
    )

    assert list(group_by_src_ip(records)) == ["203.0.113.25", "10.0.1.42"]
    assert list(group_by_dest_ip(records)) == ["10.0.1.42", "203.0.113.25"]


def test_correlate_covers_every_field() -> None:
    records = make_evidence(
        make_event(user="alpha", host="wks01", src_ip="203.0.113.25"),
        make_event(user="alpha", host="wks02", dest_ip="10.0.1.42"),
    )

    grouped = correlate(records)

    assert set(grouped) == set(CORRELATABLE_FIELDS)
    assert len(grouped["user"]["alpha"]) == 2
    assert set(grouped["host"]) == {"wks01", "wks02"}
    assert list(grouped["src_ip"]) == ["203.0.113.25"]
    assert list(grouped["dest_ip"]) == ["10.0.1.42"]


def test_correlate_of_nothing_yields_empty_groups() -> None:
    grouped = correlate([])

    assert grouped == {field: {} for field in CORRELATABLE_FIELDS}


def test_distinct_values_is_sorted_and_excludes_unset() -> None:
    records = make_evidence(
        make_event(user="zulu"),
        make_event(user=None),
        make_event(user="alpha"),
        make_event(user="zulu"),
    )

    assert distinct_values(records, "user") == ["alpha", "zulu"]


def test_shared_value_groups_keeps_only_connecting_values() -> None:
    records = make_evidence(
        make_event(host="wks01"),
        make_event(host="wks01"),
        make_event(host="wks02"),
    )

    shared = shared_value_groups(records, "host")

    assert list(shared) == ["wks01"]
    assert len(shared["wks01"]) == 2


def test_shared_value_groups_respects_a_higher_minimum() -> None:
    records = make_evidence(
        make_event(host="wks01"),
        make_event(host="wks01"),
        make_event(host="wks02"),
        make_event(host="wks02"),
        make_event(host="wks02"),
    )

    assert list(shared_value_groups(records, "host", minimum=3)) == ["wks02"]


def test_shared_value_groups_rejects_a_minimum_below_one() -> None:
    with pytest.raises(ValueError, match="minimum must be at least 1"):
        shared_value_groups([], "host", minimum=0)


def test_field_value_reads_and_normalizes() -> None:
    record = make_evidence(make_event(user=" alpha "))[0]

    assert field_value(record, "user") == "alpha"
    assert field_value(record, "host") is None


@pytest.mark.parametrize("field", ["sourcetype", "severity", "event_name", "raw_event"])
def test_group_by_rejects_non_correlatable_fields(field: str) -> None:
    records = make_evidence(make_event(user="alpha"))

    with pytest.raises(UnknownCorrelationField, match="is not correlatable"):
        group_by(records, field)


def test_unknown_field_is_rejected_even_with_no_records() -> None:
    # Validation must not depend on a record existing to trigger it.
    with pytest.raises(UnknownCorrelationField):
        group_by([], "nonexistent")


def test_distinct_values_rejects_unknown_fields() -> None:
    with pytest.raises(UnknownCorrelationField):
        distinct_values([], "nonexistent")


def test_field_value_rejects_unknown_fields() -> None:
    record = make_evidence(make_event())[0]

    with pytest.raises(UnknownCorrelationField):
        field_value(record, "nonexistent")


def test_grouping_is_reproducible() -> None:
    records = make_evidence(
        make_event(user="alpha"), make_event(user="beta"), make_event(user="alpha")
    )

    first = group_by_user(records)
    second = group_by_user(records)

    assert list(first) == list(second)
    assert [r.evidence_id for r in first["alpha"]] == [
        r.evidence_id for r in second["alpha"]
    ]
