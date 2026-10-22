import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import generate_software_list_from_spdx3 as generator


class GeneratedUpdatesTests(unittest.TestCase):
    def test_readme_uses_compact_columns_and_five_latest_history_rows(self):
        cves = ["CVE-2026-109618", "CVE-2026-109619"]
        entries = [
            {
                "supplier": "Vendor",
                "product": f"Product {index}",
                "version": "1.0",
                "notes": "Deployment scope",
                "links": "[source](<https://example.org/advisory>)",
                cves[0]: "Vulnerable",
                cves[1]: "Fix",
            }
            for index in range(7)
        ]
        events = [
            {"date_time": "2026-10-21 10:00:00 +0200", "entries": entries[:2]},
            {"date_time": "2026-10-22 10:00:00 +0200", "entries": entries[2:]},
        ]
        latest = generator.latest_update_entries(events)
        rendered = generator.render_readme_updates(cves, latest)
        table = [line for line in rendered.splitlines() if line.startswith("|")]
        self.assertEqual(table[:2], generator.readme_table_header(cves))
        self.assertEqual(len(table[2:]), 5)
        self.assertEqual(latest, generator.history_rows(events)[:5])
        self.assertIn("|Vulnerable/Fix|[source]", rendered)
        self.assertNotIn("| Notes |", rendered)
        self.assertNotIn("Deployment scope", rendered)
        self.assertIn("software/changelog_software_list.md", rendered)


class GeneratedListsTests(unittest.TestCase):
    def setUp(self):
        self.document = {
            "@graph": [
                {
                    "type": "Organization",
                    "spdxId": "urn:test:org:wordpress",
                    "name": "WordPress",
                },
                {
                    "type": "Organization",
                    "spdxId": "urn:test:org:php",
                    "name": "The PHP Group",
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:test:package:wordpress",
                    "name": "WordPress",
                    "suppliedBy": "urn:test:org:wordpress",
                    "summary": "Requires PHP ^7.4|^8.0.",
                    "externalRef": [
                        {
                            "type": "ExternalRef",
                            "locator": ["https://example.test/wordpress"],
                        }
                    ],
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:test:package:php",
                    "name": "PHP core",
                    "suppliedBy": "urn:test:org:php",
                    "software_packageVersion": "8.5.10",
                },
                {
                    "type": "security_Vulnerability",
                    "spdxId": "urn:test:vuln:CVE-2026-109618",
                    "name": "CVE-2026-109618",
                },
                {
                    "type": "security_VexUnderInvestigationVulnAssessmentRelationship",
                    "spdxId": "urn:test:vex:1",
                    "from": "urn:test:vuln:CVE-2026-109618",
                    "to": ["urn:test:package:wordpress", "urn:test:package:php"],
                    "relationshipType": "underInvestigationFor",
                    "security_statusNotes": "PHP relationship confirmed; CVE match unknown",
                },
            ]
        }

    def test_writes_index_and_alphabetical_pages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            total, counts = generator.write_lists(self.document, output_dir)

            self.assertEqual(total, 2)
            self.assertEqual(counts["T"], 1)
            self.assertEqual(counts["W"], 1)
            index = (output_dir / "software_list.md").read_text()
            self.assertIn(generator.TITLE, index)
            self.assertIn("[A](software_list_a.md)", index)
            w_page = (output_dir / "software_list_w.md").read_text()
            self.assertIn("|WordPress|WordPress||Investigation|", w_page)
            self.assertIn("unknown<br>Requires PHP ^7.4\\|^8.0.", w_page)
            self.assertIn("[source](<https://example.test/wordpress>)", w_page)

    def test_resolves_bare_filename_from_default_spdx_directory(self):
        self.assertEqual(
            generator.resolve_spdx_path(Path("inventory.spdx3.json")),
            Path("software") / "spdx" / "inventory.spdx3.json",
        )

    def test_keeps_explicit_spdx_path(self):
        self.assertEqual(
            generator.resolve_spdx_path(Path("custom") / "inventory.spdx3.json"),
            Path("custom") / "inventory.spdx3.json",
        )

    def test_renders_locatorless_external_reference_comment_as_plain_text(self):
        self.assertEqual(
            generator.external_links(
                {
                    "externalRef": [
                        {
                            "type": "ExternalRef",
                            "externalRefType": "other",
                            "comment": "Reported to NCSC-NL by trusted party; no official vendor information available.",
                        }
                    ]
                }
            ),
            "Reported to NCSC-NL by trusted party; no official vendor information available.",
        )

    def test_rejects_conflicting_statuses(self):
        self.document["@graph"].append(
            {
                "type": "security_VexAffectedVulnAssessmentRelationship",
                "spdxId": "urn:test:vex:2",
                "from": "urn:test:vuln:CVE-2026-109618",
                "to": ["urn:test:package:wordpress"],
                "relationshipType": "affects",
            }
        )
        with self.assertRaises(generator.GenerationError):
            generator.build_entries(self.document)


class MainlineHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="php2shell-history-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory = self.root / "inventory.json"
        self.git_path = generator.git_executable()
        self.git("init", "-b", "main")
        self.document = {
            "@graph": [
                {"type": "Organization", "spdxId": "org", "name": "Vendor"},
                {"type": "software_Package", "spdxId": "pkg", "name": "Product", "suppliedBy": "org"},
                {"type": "security_Vulnerability", "spdxId": "cve", "name": "CVE-2026-109618"},
                {
                    "type": "security_VexUnderInvestigationVulnAssessmentRelationship",
                    "spdxId": "vex", "from": "cve", "to": ["pkg"],
                    "relationshipType": "underInvestigationFor",
                },
            ]
        }
        self.commit_inventory("Initial inventory", "2026-10-21T10:00:00+02:00")
        self.git("branch", "pr")
        self.document["@graph"][-1].update(
            type="security_VexFixedVulnAssessmentRelationship", relationshipType="fixedIn"
        )
        self.commit_inventory("Record fixed status", "2026-10-21T11:00:00+02:00")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.git("switch", "pr")
        self.git("merge", "--no-ff", "-m", "Merge main into PR", "main",
                 timestamp="2026-10-22T12:00:00+02:00")

    def git(self, *args, timestamp="2026-10-21T09:00:00+02:00"):
        return subprocess.run(
            [self.git_path, "-C", str(self.root), "-c", "user.name=Test Author",
             "-c", "user.email=test@example.org", "-c", "commit.gpgsign=false", *args],
            check=True, capture_output=True, text=True, encoding="utf-8",
            env={**os.environ, "GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_DATE": timestamp},
        ).stdout

    def commit_inventory(self, message, timestamp):
        self.inventory.write_text(json.dumps(self.document, indent=2) + "\n", encoding="utf-8")
        self.git("add", "inventory.json")
        self.git("commit", "-m", message, timestamp=timestamp)

    def test_mainline_ref_preserves_update_time_across_pr_merge(self):
        with patch.object(generator, "repository_root", return_value=self.root):
            _, events = generator.build_status_history(
                self.document, self.inventory, history_ref="origin/main"
            )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["date_time"], "2026-10-21 11:00:00 +0200")
        self.assertEqual(events[-1]["entries"][0]["CVE-2026-109618"], "Fix")

    def test_unmerged_status_change_is_included_after_mainline_history(self):
        pending = copy.deepcopy(self.document)
        pending["@graph"][-1].update(
            type="security_VexAffectedVulnAssessmentRelationship", relationshipType="affects"
        )
        with patch.object(generator, "repository_root", return_value=self.root):
            _, events = generator.build_status_history(
                pending, self.inventory, history_ref="origin/main"
            )
        self.assertEqual(len(events), 3)
        self.assertEqual(events[-2]["date_time"], "2026-10-21 11:00:00 +0200")
        self.assertEqual(events[-1]["entries"][0]["CVE-2026-109618"], "Vulnerable")


if __name__ == "__main__":
    unittest.main()
