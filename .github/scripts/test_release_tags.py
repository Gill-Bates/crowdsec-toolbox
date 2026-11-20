#!/usr/bin/env python3
#
# .github/scripts/test_release_tags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import release_notes
import release_tags

AMD64 = "sha256:" + "a" * 64
ARM64 = "sha256:" + "b" * 64
INDEX = "sha256:" + "c" * 64
IMAGE = "giiibates/crowdsec-toolbox"


def manifest_json(*descriptors: dict) -> str:
    return json.dumps({"digest": INDEX, "manifests": list(descriptors)})


def descriptor(architecture: str, digest: str, operating_system: str = "linux") -> dict:
    return {"digest": digest, "platform": {"architecture": architecture, "os": operating_system}}


class ReleaseTagParsingTest(unittest.TestCase):
    def test_arch_fragments_and_candidate_tags_do_not_block_latest(self):
        tags = [
            "abuse-reporter-2.0.0-amd64",
            "metrics-exporter-2.0.0-arm64",
            "abuse-reporter-candidate-123456",
            "metrics-exporter-latest",
        ]

        self.assertEqual(release_tags.newer_stable_release_tags("1.9.0", tags), [])

    def test_real_release_tag_from_either_tool_blocks_older_latest(self):
        self.assertEqual(
            release_tags.newer_stable_release_tags("1.9.0", ["metrics-exporter-2.0.0"]),
            ["metrics-exporter-2.0.0"],
        )

    def test_numeric_prerelease_identifiers_sort_numerically(self):
        self.assertGreater(
            release_tags.release_tag_key("abuse-reporter-1.2.3-rc.10"),
            release_tags.version_key("1.2.3-rc.2"),
        )

    def test_newest_output_ignores_a_newer_prerelease(self):
        environment = {"VERSION": "1.9.0", "DOCKERHUB_USERNAME": "owner", "DOCKERHUB_TOKEN": "token"}
        with (
            patch.object(release_tags, "_require_env", side_effect=environment.__getitem__),
            patch.object(release_tags, "list_published_tags", return_value=["metrics-exporter-2.0.0-rc.1"]),
            patch.object(release_tags, "write_outputs") as write_outputs,
        ):
            self.assertEqual(release_tags.run_newest(), 0)

        write_outputs.assert_called_once_with({"is_newest": "true"})

    def test_candidate_tag_is_tool_and_run_scoped(self):
        self.assertEqual(release_tags.candidate_tag("abuse-reporter", "123456"), "abuse-reporter-candidate-123456")
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "unsupported tool"):
            release_tags.candidate_tag("unknown", "123456")
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "digits"):
            release_tags.candidate_tag("abuse-reporter", "123456/other")


class ManifestVerificationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="release-tags-test-")
        self.addCleanup(self.temp_dir.cleanup)
        self.digest_dir = Path(self.temp_dir.name)
        (self.digest_dir / "abuse-reporter-amd64").write_text(f"{AMD64}\n", encoding="utf-8")
        (self.digest_dir / "abuse-reporter-arm64").write_text(f"{ARM64}\n", encoding="utf-8")

    def test_json_manifest_includes_expected_platforms_and_ignores_attestations(self):
        output = manifest_json(
            descriptor("amd64", AMD64),
            descriptor("arm64", ARM64),
            descriptor("unknown", "sha256:" + "d" * 64, "unknown"),
        )

        self.assertEqual(
            release_tags.parse_manifest_inspection(output),
            (INDEX, {"linux/amd64": AMD64, "linux/arm64": ARM64}),
        )

    def test_existing_version_tag_is_idempotent_for_the_same_digest(self):
        expected = release_tags.expected_manifest(self.digest_dir, "abuse-reporter")
        inspect = Mock(return_value=(INDEX, expected))
        tag = Mock()

        release_tags.publish_verified_version_tag(
            IMAGE,
            "abuse-reporter",
            "1.9.0",
            INDEX,
            expected,
            already_published=True,
            exists=Mock(),
            inspect=inspect,
            tag=tag,
        )

        inspect.assert_called_once_with(f"{IMAGE}:abuse-reporter-1.9.0")
        tag.assert_not_called()

    def test_existing_version_tag_with_a_different_digest_is_rejected(self):
        expected = release_tags.expected_manifest(self.digest_dir, "abuse-reporter")
        inspect = Mock(return_value=(AMD64, expected))
        tag = Mock()

        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "already points to a different digest"):
            release_tags.publish_verified_version_tag(
                IMAGE,
                "abuse-reporter",
                "1.9.0",
                INDEX,
                expected,
                already_published=True,
                exists=Mock(),
                inspect=inspect,
                tag=tag,
            )

        tag.assert_not_called()

    def test_version_tag_missing_from_the_list_but_present_with_another_digest_is_not_overwritten(self):
        expected = release_tags.expected_manifest(self.digest_dir, "abuse-reporter")
        inspect = Mock(return_value=(AMD64, expected))
        tag = Mock()
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "already points to a different digest"):
            release_tags.publish_verified_version_tag(
                IMAGE,
                "abuse-reporter",
                "1.9.0",
                INDEX,
                expected,
                already_published=False,
                exists=lambda name: name == "abuse-reporter-1.9.0",
                inspect=inspect,
                tag=tag,
            )
        tag.assert_not_called()

    def test_failed_version_tag_lookup_stops_before_any_write(self):
        expected = release_tags.expected_manifest(self.digest_dir, "abuse-reporter")
        tag = Mock()
        exists = Mock(side_effect=release_tags.ReleaseTagsError("Docker Hub API returned HTTP 500"))
        with self.assertRaises(release_tags.ReleaseTagsError):
            release_tags.publish_verified_version_tag(
                IMAGE,
                "abuse-reporter",
                "1.9.0",
                INDEX,
                expected,
                already_published=False,
                exists=exists,
                inspect=Mock(),
                tag=tag,
            )
        tag.assert_not_called()

    def test_tag_lookup_treats_404_as_free_and_other_errors_as_failures(self):
        with patch.object(release_tags, "_request_json", return_value=(404, None)):
            self.assertFalse(release_tags.tag_exists("owner", "token", "abuse-reporter-1.9.0"))
        with patch.object(release_tags, "_request_json", return_value=(200, {"name": "abuse-reporter-1.9.0"})):
            self.assertTrue(release_tags.tag_exists("owner", "token", "abuse-reporter-1.9.0"))
        with (
            patch.object(release_tags, "_request_json", return_value=(204, None)),
            self.assertRaises(release_tags.ReleaseTagsError),
        ):
            release_tags.tag_exists("owner", "token", "abuse-reporter-1.9.0")

    def test_duplicate_platform_is_rejected(self):
        output = manifest_json(descriptor("amd64", AMD64), descriptor("amd64", ARM64))

        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "duplicate platform"):
            release_tags.parse_manifest_inspection(output)

    def test_missing_architecture_is_rejected(self):
        expected = release_tags.expected_manifest(self.digest_dir, "abuse-reporter")

        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "does not match"):
            release_tags.verify_manifest(expected, {"linux/amd64": AMD64}, "candidate")

    def test_candidate_creation_uses_build_digests_and_verifies_registry_result(self):
        expected = release_tags.expected_manifest(self.digest_dir, "abuse-reporter")
        docker = Mock(return_value="")
        inspect = Mock(return_value=(INDEX, expected))
        with (
            patch.object(release_tags, "docker_command", docker),
            patch.object(release_tags, "inspect_manifest", inspect),
        ):
            digest = release_tags.create_candidate(IMAGE, "abuse-reporter", "1.9.0", "123456", self.digest_dir)

        self.assertEqual(digest, INDEX)
        command = docker.call_args.args[0]
        self.assertEqual(command[0:3], ["buildx", "imagetools", "create"])
        self.assertIn("--tag", command)
        self.assertIn(f"{IMAGE}:abuse-reporter-candidate-123456", command)
        self.assertIn(f"{IMAGE}@{AMD64}", command)
        self.assertIn(f"{IMAGE}@{ARM64}", command)


class PushedDigestParsingTest(unittest.TestCase):
    def test_extracts_digest_reported_by_successful_push(self):
        output = f"latest: digest: {AMD64} size: 1234\n"
        self.assertEqual(release_tags.parse_push_digest(output), AMD64)

    def test_rejects_push_output_without_one_digest(self):
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "one image digest"):
            release_tags.parse_push_digest("The push refers to repository [example/image]\n")

    def test_push_command_writes_digest_file(self):
        with tempfile.TemporaryDirectory(prefix="release-push-digest-test-") as directory:
            root = Path(directory)
            digest_file = root / "digests" / "abuse-reporter-amd64"
            push_output_file = root / "docker-push.log"
            push_output_file.write_text(f"tag: digest: {AMD64} size: 1", encoding="utf-8")
            with patch.dict(
                "os.environ",
                {
                    "PUSH_OUTPUT_FILE": str(push_output_file),
                    "DIGEST_FILE": str(digest_file),
                },
            ):
                release_tags.run_record_pushed_digest()

            self.assertEqual(digest_file.read_text(encoding="utf-8"), AMD64)


class PromotionOrderingTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="release-promotion-test-")
        self.addCleanup(self.temp_dir.cleanup)
        self.digest_dir = Path(self.temp_dir.name)
        for tool in release_tags.TOOLS:
            (self.digest_dir / f"{tool}-amd64").write_text(f"{AMD64}\n", encoding="utf-8")
            (self.digest_dir / f"{tool}-arm64").write_text(f"{ARM64}\n", encoding="utf-8")
        self.expected = {"linux/amd64": AMD64, "linux/arm64": ARM64}

    def test_candidates_are_verified_before_listing_and_public_tag_writes(self):
        events = []

        def inspect(reference):
            events.append(("inspect", reference))
            return INDEX, self.expected

        def list_tags():
            events.append(("list-tags",))
            return []

        def tag(_image, name, digest):
            events.append(("tag", name, digest))

        is_newest = release_tags.promote_release(
            IMAGE,
            "1.9.0",
            "123456",
            self.digest_dir,
            list_tags,
            inspect,
            tag,
            lambda _tag: False,
        )

        self.assertTrue(is_newest)
        tag_positions = [index for index, event in enumerate(events) if event[0] == "tag"]
        listing_position = next(index for index, event in enumerate(events) if event[0] == "list-tags")
        candidates_before_listing = [
            event[1] for event in events[:listing_position] if event[0] == "inspect" and "candidate-" in event[1]
        ]
        self.assertEqual(
            set(candidates_before_listing),
            {
                f"{IMAGE}:abuse-reporter-candidate-123456",
                f"{IMAGE}:metrics-exporter-candidate-123456",
            },
        )
        self.assertLess(listing_position, tag_positions[0])
        candidate_positions = [
            index for index, event in enumerate(events) if event[0] == "inspect" and "candidate-" in event[1]
        ]
        self.assertLess(max(candidate_positions), tag_positions[0])
        self.assertEqual(
            [events[index][1] for index in tag_positions],
            [
                "abuse-reporter-1.9.0",
                "metrics-exporter-1.9.0",
                "abuse-reporter-latest",
                "metrics-exporter-latest",
            ],
        )

    def test_candidate_mismatch_prevents_public_tag_writes(self):
        events = []

        def inspect(reference):
            events.append(("inspect", reference))
            if "metrics-exporter-candidate" in reference:
                return INDEX, {"linux/amd64": AMD64}
            return INDEX, self.expected

        def list_tags():
            events.append(("list-tags",))
            return []

        tag = Mock(side_effect=lambda *_: events.append(("tag",)))
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "does not match"):
            release_tags.promote_release(
                IMAGE,
                "1.9.0",
                "123456",
                self.digest_dir,
                list_tags,
                inspect,
                tag,
                lambda _tag: False,
            )

        self.assertNotIn(("list-tags",), events)
        tag.assert_not_called()

    def test_candidate_change_after_fresh_listing_prevents_public_tag_writes(self):
        events = []
        candidate_checks = dict.fromkeys(release_tags.TOOLS, 0)

        def inspect(reference):
            events.append(("inspect", reference))
            tool = next(tool for tool in release_tags.TOOLS if f"{tool}-candidate" in reference)
            candidate_checks[tool] += 1
            if tool == "metrics-exporter" and candidate_checks[tool] == 2:
                return INDEX, {"linux/amd64": AMD64}
            return INDEX, self.expected

        def list_tags():
            events.append(("list-tags",))
            return []

        tag = Mock()
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "does not match"):
            release_tags.promote_release(
                IMAGE,
                "1.9.0",
                "123456",
                self.digest_dir,
                list_tags,
                inspect,
                tag,
                lambda _tag: False,
            )

        self.assertIn(("list-tags",), events)
        tag.assert_not_called()

    def test_all_existing_version_tags_are_checked_before_any_public_tag_write(self):
        existing = ["abuse-reporter-1.9.0", "metrics-exporter-1.9.0"]

        def inspect(reference):
            if reference.endswith("metrics-exporter-1.9.0"):
                return AMD64, self.expected
            return INDEX, self.expected

        tag = Mock()
        with self.assertRaisesRegex(release_tags.ReleaseTagsError, "already points to a different digest"):
            release_tags.promote_release(
                IMAGE,
                "1.9.0",
                "123456",
                self.digest_dir,
                lambda: existing,
                inspect,
                tag,
                lambda _tag: False,
            )

        tag.assert_not_called()

    def test_older_stable_release_does_not_move_latest(self):
        tags = []
        inspect = Mock(return_value=(INDEX, self.expected))
        tag = Mock(side_effect=lambda _image, name, _digest: tags.append(name))
        is_newest = release_tags.promote_release(
            IMAGE,
            "1.9.0",
            "123456",
            self.digest_dir,
            lambda: ["metrics-exporter-2.0.0"],
            inspect,
            tag,
            lambda _tag: False,
        )

        self.assertFalse(is_newest)
        self.assertEqual(tags, ["abuse-reporter-1.9.0", "metrics-exporter-1.9.0"])

    def test_newer_prerelease_does_not_block_stable_latest(self):
        tags = []
        inspect = Mock(return_value=(INDEX, self.expected))
        tag = Mock(side_effect=lambda _image, name, _digest: tags.append(name))

        is_newest = release_tags.promote_release(
            IMAGE,
            "1.9.0",
            "123456",
            self.digest_dir,
            lambda: ["metrics-exporter-2.0.0-rc.1"],
            inspect,
            tag,
            lambda _tag: False,
        )

        self.assertTrue(is_newest)
        self.assertEqual(
            tags,
            [
                "abuse-reporter-1.9.0",
                "metrics-exporter-1.9.0",
                "abuse-reporter-latest",
                "metrics-exporter-latest",
            ],
        )

    def test_prerelease_gets_version_tags_but_not_latest(self):
        tags = []
        inspect = Mock(return_value=(INDEX, self.expected))
        tag = Mock(side_effect=lambda _image, name, _digest: tags.append(name))
        is_newest = release_tags.promote_release(
            IMAGE,
            "1.9.0-rc.1",
            "123456",
            self.digest_dir,
            list,
            inspect,
            tag,
            lambda _tag: False,
        )

        self.assertTrue(is_newest)
        self.assertEqual(tags, ["abuse-reporter-1.9.0-rc.1", "metrics-exporter-1.9.0-rc.1"])


class ReleaseNotesCompositionTest(unittest.TestCase):
    def test_combines_both_version_sections_and_appends_cloc(self):
        abuse = """## [1.0.2] - 2026-11-19

- `New` Abuse Reporter release entry.
- `Security` Abuse Reporter security entry.

## [1.0.1] - 2026-09-25
- Previous release content.
"""
        metrics = """## [1.0.2] - 2026-11-19

- `New` Metrics Exporter release entry.
- `Fix` Metrics Exporter fix.

## [1.0.1] - 2026-09-25
- Previous release content.
"""

        notes = release_notes.compose_release_notes("1.0.2", abuse, metrics, "1 file, 2 lines")

        self.assertIn("## [1.0.2] - 2026-11-19", notes)
        self.assertLess(notes.index("### Abuse Reporter"), notes.index("### Metrics Exporter"))
        self.assertLess(notes.index("### Metrics Exporter"), notes.index("### Code Statistics (cloc)"))
        self.assertIn("`Security` Abuse Reporter security entry.", notes)
        self.assertIn("`Fix` Metrics Exporter fix.", notes)
        self.assertIn("1 file, 2 lines", notes)
        self.assertNotIn("Previous release content", notes)

    def test_collapsed_previous_versions_stay_out_of_the_notes(self):
        def changelog(entry: str) -> str:
            return (
                f"## [1.0.3] - 2026-11-19\n\n- `New` {entry}\n\n"
                '<details markdown="1">\n<summary>Previous versions...</summary>\n\n'
                "## [1.0.2] - 2026-11-01\n\n- Old entry.\n\n</details>\n"
            )

        notes = release_notes.compose_release_notes("1.0.3", changelog("Abuse"), changelog("Metrics"), "cloc table")

        self.assertNotIn("details", notes)
        self.assertNotIn("Previous versions", notes)
        self.assertNotIn("Old entry", notes)
        self.assertIn("cloc table", notes)

    def test_requires_matching_release_dates(self):
        abuse = "## [1.0.2] - 2026-11-19\n\n- `New` Abuse Reporter entry."
        metrics = "## [1.0.2] - 2026-11-20\n\n- `New` Metrics Exporter entry."

        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "different release dates"):
            release_notes.compose_release_notes("1.0.2", abuse, metrics, "1 file, 2 lines")

    def test_requires_cloc_output(self):
        changelog = "## [1.0.2] - 2026-11-19\n\n- `New` Release entry."

        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "cloc output is empty"):
            release_notes.compose_release_notes("1.0.2", changelog, changelog, "  \n")


if __name__ == "__main__":
    unittest.main()
