"""Tests for bubble.name_normalize — matching ES DB names ↔ display names."""
from __future__ import annotations

from bubblepwn.bubble.name_normalize import (
    FieldKey,
    key_for_db,
    key_for_display,
    match,
    pair,
)


class TestKeyForDb:
    def test_strip_text_suffix(self):
        k = key_for_db("profile_bio_text")
        assert k.stripped == "profilebio"
        assert k.type_hint == "text"
        assert k.target_type is None

    def test_strip_boolean_suffix(self):
        k = key_for_db("isneostaff_boolean")
        assert k.stripped == "isneostaff"
        assert k.without_is == "neostaff"
        assert k.type_hint == "boolean"

    def test_boolean_without_is_prefix(self):
        k = key_for_db("visible_boolean")
        assert k.stripped == "visible"
        assert k.with_is == "isvisible"
        assert k.type_hint == "boolean"

    def test_number_suffix(self):
        k = key_for_db("numendorsements_number")
        assert k.stripped == "numendorsements"
        assert k.type_hint == "number"

    def test_image_suffix(self):
        k = key_for_db("profilepic_image")
        assert k.stripped == "profilepic"
        assert k.type_hint == "image"

    def test_list_option(self):
        k = key_for_db("accldomains_list_option_acceleratordomains")
        assert k.stripped == "accldomains"
        assert k.type_hint == "list.option.acceleratordomains"
        assert k.target_type == "acceleratordomains"

    def test_custom_ref(self):
        k = key_for_db("person_custom_person")
        assert k.stripped == "person"
        assert k.type_hint == "ref.custom.person"
        assert k.target_type == "person"

    def test_list_custom(self):
        k = key_for_db("tags_list_custom_tag")
        assert k.stripped == "tags"
        assert k.type_hint == "list.custom.tag"
        assert k.target_type == "tag"

    def test_list_primitive(self):
        k = key_for_db("domains_list_text")
        assert k.stripped == "domains"
        assert k.type_hint == "list.text"

    def test_no_suffix(self):
        # Built-in Bubble fields keep their raw form.
        k = key_for_db("Slug")
        assert k.stripped == "slug"
        assert k.type_hint is None

    def test_authentication_field(self):
        k = key_for_db("authentication")
        assert k.stripped == "authentication"
        assert k.type_hint is None

    def test_user_signed_up(self):
        # Built-in Bubble field, not suffixed.
        k = key_for_db("user_signed_up")
        assert k.stripped == "usersignedup"
        assert k.type_hint is None


class TestKeyForDisplay:
    def test_simple(self):
        k = key_for_display("Profile Bio")
        assert k.stripped == "profilebio"

    def test_camel_case(self):
        k = key_for_display("isNeoStaff")
        assert k.stripped == "isneostaff"
        assert k.without_is == "neostaff"

    def test_is_prefix_boolean(self):
        k = key_for_display("isVisible")
        assert k.stripped == "isvisible"
        assert k.without_is == "visible"

    def test_strip_rename_marker_mod(self):
        k = key_for_display("Public Title mod")
        # "mod" marker is stripped before normalisation
        assert k.stripped == "publictitle"

    def test_strip_rename_marker_v2(self):
        k = key_for_display("Description v2")
        assert k.stripped == "description"

    def test_accldomains(self):
        k = key_for_display("AcclDomains")
        assert k.stripped == "accldomains"


class TestMatch:
    def test_exact_canonical(self):
        assert match("profile_bio_text", "Profile Bio")

    def test_with_is_prefix_symmetric(self):
        # DB keeps is-prefix, display keeps is-prefix.
        assert match("isneostaff_boolean", "isNeoStaff")

    def test_db_missing_is_prefix(self):
        # DB is ``visible_boolean`` but display is ``isVisible``.
        assert match("visible_boolean", "isVisible")

    def test_list_option_to_camel(self):
        assert match(
            "accldomains_list_option_acceleratordomains",
            "AcclDomains",
        )

    def test_display_rename_marker_ignored(self):
        assert match("public_title_text", "Public Title mod")

    def test_custom_ref_to_short_display(self):
        assert match("person_custom_person", "Person")

    def test_unrelated_fields_do_not_match(self):
        assert not match("profile_bio_text", "isNeoStaff")
        assert not match("numendorsements_number", "Region")

    def test_user_signed_up_both_sides(self):
        # This Bubble built-in keeps the same form in both pipelines.
        assert match("user_signed_up", "user_signed_up")

    def test_match_accepts_fieldkey(self):
        ka = key_for_db("isneostaff_boolean")
        kb = key_for_display("isNeoStaff")
        assert match(ka, kb)


class TestPair:
    def test_full_mapping_from_neo_example(self):
        # Fields observed on neo.com / Ali Partovi — the smoke test.
        db = [
            "profile_bio_text", "isneostaff_boolean", "visible_boolean",
            "numendorsements_number", "profilepic_image",
            "accldomains_list_option_acceleratordomains",
            "person_custom_person", "Slug", "authentication",
            "user_signed_up",
        ]
        disp = [
            "Profile Bio", "isNeoStaff", "isVisible",
            "numEndorsements", "Profile Pic", "AcclDomains",
            "Person", "Slug", "user_signed_up",
            "ApplyStages",  # display-only, no ES equivalent
        ]
        pairs, db_only, disp_only = pair(db, disp)
        pair_map = dict(pairs)
        assert pair_map["profile_bio_text"] == "Profile Bio"
        assert pair_map["isneostaff_boolean"] == "isNeoStaff"
        assert pair_map["visible_boolean"] == "isVisible"
        assert pair_map["numendorsements_number"] == "numEndorsements"
        assert pair_map["profilepic_image"] == "Profile Pic"
        assert pair_map[
            "accldomains_list_option_acceleratordomains"
        ] == "AcclDomains"
        assert pair_map["person_custom_person"] == "Person"
        assert pair_map["Slug"] == "Slug"
        assert pair_map["user_signed_up"] == "user_signed_up"

        # authentication is ES-only (Bubble built-in redacted on Data API)
        assert "authentication" in db_only
        # ApplyStages is display-only (fully hidden by ES privacy)
        assert "ApplyStages" in disp_only

    def test_empty_inputs(self):
        pairs, db_only, disp_only = pair([], [])
        assert pairs == [] and db_only == [] and disp_only == []

    def test_no_matches(self):
        pairs, db_only, disp_only = pair(["foo_text"], ["Bar"])
        assert pairs == []
        assert db_only == ["foo_text"]
        assert disp_only == ["Bar"]

    def test_one_match_one_disjoint_each(self):
        pairs, db_only, disp_only = pair(
            ["profile_bio_text", "only_in_db_text"],
            ["Profile Bio", "OnlyInDisplay"],
        )
        assert pairs == [("profile_bio_text", "Profile Bio")]
        assert db_only == ["only_in_db_text"]
        assert disp_only == ["OnlyInDisplay"]
