"""Payload catalog integrity tests."""

from h4ackbar.payloads import all_payloads, categories, Payload


def test_catalog_nonempty():
    p = all_payloads()
    assert len(p) > 60


def test_all_categories_covered():
    p = all_payloads()
    cats = {x.category for x in p}
    assert cats == set(categories().keys())


def test_no_empty_payload_strings():
    for p in all_payloads():
        assert isinstance(p, Payload)
        assert p.payload, f"empty payload: {p.label}"
        assert p.category
        assert p.label


def test_union_variants_have_column_probes():
    p = all_payloads()
    labels = [x.label for x in p]
    assert any("ORDER BY 1" in l for l in labels)
    assert any("UNION NULL x1" in l for l in labels)


def test_time_blind_has_all_dbms():
    p = [x for x in all_payloads() if x.category == "blind_time"]
    joined = " ".join(x.label for x in p).lower()
    for keyword in ("mysql", "pg", "mssql", "oracle", "sqlite"):
        assert keyword in joined
