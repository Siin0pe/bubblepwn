"""Tests for the ES ↔ Data API enrichment merge logic in es_audit.

Covers:
  - ``_merge_es_dataapi`` — key pairing, redacted-value preference,
    provenance tracking, @db alias emission.
  - ``_is_redacted`` — empty-object / empty-list / None detection.
  - ``_jsonl_already_enriched`` — idempotency marker detection.
  - ``_reconstruct_raw_type`` — filename → ES type canonical form.
  - ``_import_jsonl_into_sqlite`` — enriched record prioritised over
    ``_source`` when both are present.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from bubblepwn.modules.es_audit import (
    _import_jsonl_into_sqlite,
    _is_redacted,
    _jsonl_already_enriched,
    _merge_es_dataapi,
    _reconstruct_raw_type,
)


class TestIsRedacted:
    def test_none(self):
        assert _is_redacted(None)

    def test_empty_dict(self):
        assert _is_redacted({})

    def test_empty_list(self):
        assert _is_redacted([])

    def test_non_empty_dict(self):
        assert not _is_redacted({"email": "a@b.c"})

    def test_non_empty_list(self):
        assert not _is_redacted(["a"])

    def test_empty_string_not_redacted(self):
        # Empty string is a legitimate set value in Bubble (different from
        # unset) — don't treat it as redacted.
        assert not _is_redacted("")

    def test_zero_not_redacted(self):
        assert not _is_redacted(0)

    def test_false_not_redacted(self):
        assert not _is_redacted(False)


class TestMergeEsDataapi:
    def test_union_of_disjoint_keys(self):
        es = {"authentication": {}}
        da = {"Profile Bio": "hello"}
        merged, prov, new = _merge_es_dataapi(es, da)
        assert merged == {"authentication": {}, "Profile Bio": "hello"}
        assert prov == {"authentication": "es", "Profile Bio": "dataapi"}
        assert new == 1

    def test_match_pair_prefers_dataapi_display_name(self):
        es = {"profile_bio_text": "from ES"}
        da = {"Profile Bio": "from DA"}
        merged, prov, new = _merge_es_dataapi(es, da)
        assert "Profile Bio" in merged
        assert merged["Profile Bio"] == "from DA"
        # DB name surfaces as an alias column so downstream consumers see
        # both conventions.
        assert merged["Profile Bio@db"] == "from ES"
        assert prov["Profile Bio"] == "both"
        assert new == 0

    def test_redacted_es_prefers_dataapi_value(self):
        # ES says {} (redacted), Data API has content → use Data API.
        es = {"authentication": {}}
        da = {"authentication": {"email": {"email": "a@b.c"}}}
        merged, prov, _ = _merge_es_dataapi(es, da)
        assert merged["authentication"] == {"email": {"email": "a@b.c"}}
        assert prov["authentication"] == "both"

    def test_redacted_dataapi_prefers_es_value(self):
        # Inverse: ES has content, Data API redacted it → use ES.
        es = {"region_text": "San Francisco"}
        da = {"Region": None}
        merged, _, _ = _merge_es_dataapi(es, da)
        # Both exist under matched pair, ES value wins because DA is None.
        assert merged["Region"] == "San Francisco"

    def test_unmatched_es_side_stays_as_is(self):
        es = {"ultra_obscure_field_text": "stays"}
        da = {}
        merged, prov, new = _merge_es_dataapi(es, da)
        assert merged == {"ultra_obscure_field_text": "stays"}
        assert prov == {"ultra_obscure_field_text": "es"}
        assert new == 0

    def test_unmatched_dataapi_side_counts_as_new_fields(self):
        es = {}
        da = {"JobSeekingStatus": "active", "Company": "xyz"}
        merged, prov, new = _merge_es_dataapi(es, da)
        assert merged == {"JobSeekingStatus": "active", "Company": "xyz"}
        assert new == 2

    def test_is_prefix_mismatch_still_merges(self):
        # visible_boolean ↔ isVisible is the classic case.
        es = {"visible_boolean": True}
        da = {"isVisible": True}
        merged, prov, _ = _merge_es_dataapi(es, da)
        # Display name wins as the canonical key.
        assert "isVisible" in merged
        assert merged["isVisible"] is True
        assert prov["isVisible"] == "both"

    def test_list_option_pairs_with_short_display(self):
        es = {"accldomains_list_option_acceleratordomains": ["a", "b"]}
        da = {"AcclDomains": ["a", "b"]}
        merged, _, _ = _merge_es_dataapi(es, da)
        assert "AcclDomains" in merged
        assert merged["AcclDomains"] == ["a", "b"]

    def test_meta_map_resolves_bubble_managed_alias(self):
        # 'name_first_text' and 'Profile First Name' share no structure,
        # so the heuristic matcher can't pair them. /meta publishes the
        # canonical mapping — pass it in and the pair should match.
        es = {"name_first_text": "Ali"}
        da = {"Profile First Name": "Ali"}
        meta_map = {"name_first_text": "Profile First Name"}
        merged, prov, new = _merge_es_dataapi(es, da, meta_map=meta_map)
        assert "Profile First Name" in merged
        assert merged["Profile First Name"] == "Ali"
        assert prov["Profile First Name"] == "both"
        assert new == 0

    def test_meta_map_takes_priority_over_heuristic(self):
        # Heuristic would pair profile_bio_text ↔ "Profile Bio".
        # meta_map forces a different pairing (synthetic example) — verify
        # the authoritative map wins.
        es = {"profile_bio_text": "heuristic would match this"}
        da = {"Profile Bio": "heuristic target", "Something Else": "meta target"}
        meta_map = {"profile_bio_text": "Something Else"}
        merged, prov, _ = _merge_es_dataapi(es, da, meta_map=meta_map)
        assert "Something Else" in merged
        assert prov["Something Else"] == "both"
        # 'Profile Bio' is now an unpaired Data API field.
        assert prov.get("Profile Bio") == "dataapi"

    def test_meta_map_entries_not_present_are_ignored(self):
        # meta_map may list fields that didn't come back on this record
        # (privacy-blocked); fall through to the heuristic matcher.
        es = {"profile_bio_text": "x"}
        da = {"Profile Bio": "y"}
        meta_map = {"unrelated_field_text": "Unrelated"}
        merged, prov, _ = _merge_es_dataapi(es, da, meta_map=meta_map)
        assert prov["Profile Bio"] == "both"
        assert merged["Profile Bio"] == "y"


class TestJsonlAlreadyEnriched:
    def test_enriched_file(self, tmp_path):
        f = tmp_path / "dump.jsonl"
        f.write_text(
            json.dumps({"_id": "x", "_source": {}, "_enrich": {"merged": {}}})
            + "\n",
            encoding="utf-8",
        )
        assert _jsonl_already_enriched(f) is True

    def test_raw_es_file(self, tmp_path):
        f = tmp_path / "dump.jsonl"
        f.write_text(
            json.dumps({"_id": "x", "_source": {"a": 1}}) + "\n",
            encoding="utf-8",
        )
        assert _jsonl_already_enriched(f) is False

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("", encoding="utf-8")
        assert _jsonl_already_enriched(f) is False

    def test_missing_file(self, tmp_path):
        assert _jsonl_already_enriched(tmp_path / "nope.jsonl") is False

    def test_blank_lines_before_first_record(self, tmp_path):
        f = tmp_path / "dump.jsonl"
        f.write_text(
            "\n\n"
            + json.dumps({"_id": "x", "_enrich": {"merged": {}}}) + "\n",
            encoding="utf-8",
        )
        assert _jsonl_already_enriched(f) is True


class TestReconstructRawType:
    def test_user(self):
        assert _reconstruct_raw_type("user") == "user"

    def test_custom_dot(self):
        assert _reconstruct_raw_type("custom.user_profile") == "custom.user_profile"

    def test_custom_underscore_legacy(self):
        assert _reconstruct_raw_type("custom_customer") == "custom.customer"

    def test_option_dot(self):
        assert _reconstruct_raw_type("option.status") == "option.status"

    def test_unknown_stem_passes_through(self):
        assert _reconstruct_raw_type("weird_name") == "weird_name"


class TestImportJsonlIntoSqliteUsesMerged:
    def test_enriched_record_populates_merged_columns(self, tmp_path):
        """When a JSONL record has ``_enrich.merged``, the SQLite table
        should be built from the merged view — exposing display-name
        columns that ES ``_source`` alone would not contain.
        """
        jf = tmp_path / "user.jsonl"
        jf.write_text(
            json.dumps({
                "_id": "1x2y",
                "_type": "user",
                "_source": {
                    "profile_bio_text": "raw es bio",
                    "authentication": {},
                },
                "_enrich": {
                    "dataapi_status": 200,
                    "merged": {
                        "Profile Bio": "from DA",
                        "Profile Bio@db": "raw es bio",
                        "ApplyStages": ["interview"],
                        "authentication": {},
                    },
                    "provenance": {
                        "Profile Bio": "both",
                        "ApplyStages": "dataapi",
                        "authentication": "es",
                    },
                },
            }) + "\n",
            encoding="utf-8",
        )

        db = tmp_path / "out.sqlite"
        conn = sqlite3.connect(db)
        rows, cols = _import_jsonl_into_sqlite(conn, jf, "t_user")

        assert rows == 1
        # Merged view columns present.
        colnames = {r[1] for r in conn.execute('PRAGMA table_info("t_user")')}
        assert "Profile Bio" in colnames
        assert "ApplyStages" in colnames
        assert "Profile Bio@db" in colnames
        assert "_id" in colnames
        # Values came from the Data API merge, not just ES.
        row = conn.execute(
            'SELECT "Profile Bio", "ApplyStages", "_id" FROM t_user'
        ).fetchone()
        assert row[0] == "from DA"
        # Lists get JSON-encoded by the importer.
        assert json.loads(row[1]) == ["interview"]
        assert row[2] == "1x2y"
        conn.close()

    def test_unenriched_record_still_imports_from_source(self, tmp_path):
        jf = tmp_path / "user.jsonl"
        jf.write_text(
            json.dumps({
                "_id": "2x3y",
                "_type": "user",
                "_source": {"profile_bio_text": "only es"},
            }) + "\n",
            encoding="utf-8",
        )
        db = tmp_path / "out.sqlite"
        conn = sqlite3.connect(db)
        rows, _ = _import_jsonl_into_sqlite(conn, jf, "t_user")
        assert rows == 1
        colnames = {r[1] for r in conn.execute('PRAGMA table_info("t_user")')}
        assert "profile_bio_text" in colnames
        assert "_id" in colnames
        row = conn.execute(
            'SELECT "profile_bio_text", "_id" FROM t_user'
        ).fetchone()
        assert row == ("only es", "2x3y")
        conn.close()

    def test_envelope_id_added_when_merged_omits_it(self, tmp_path):
        """Data API responses don't always include ``_id`` in the body —
        but the ES envelope does, and the importer must carry it through
        so joins on ``_id`` keep working across tables.
        """
        jf = tmp_path / "user.jsonl"
        jf.write_text(
            json.dumps({
                "_id": "env-id-999",
                "_type": "user",
                "_source": {"a": 1},
                "_enrich": {
                    "dataapi_status": 200,
                    "merged": {"Profile Bio": "x"},  # no _id here
                },
            }) + "\n",
            encoding="utf-8",
        )
        db = tmp_path / "out.sqlite"
        conn = sqlite3.connect(db)
        _import_jsonl_into_sqlite(conn, jf, "t_user")
        row = conn.execute('SELECT "_id" FROM t_user').fetchone()
        assert row[0] == "env-id-999"
        conn.close()
