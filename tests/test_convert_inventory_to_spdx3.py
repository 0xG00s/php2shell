import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "tools" / "convert_inventory_to_spdx3.py"
SPEC = importlib.util.spec_from_file_location("convert_inventory_to_spdx3", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class ConvertInventoryToSpdx3Tests(unittest.TestCase):
    def setUp(self):
        self.inventory = {
            "schema_version": "1.17",
            "project": "Project Initium",
            "title": "PHP downstream inventory",
            "scope": "Cross-product inventory.",
            "status": "Preliminary inventory.",
            "last_updated": "2026-10-21T10:15:16.953462Z",
            "vulnerability_reviews": {
                "id": "CVE-REVIEW-1",
                "stage": "Pre-release initial information",
                "cve_ids": ["CVE-2026-109618", "CVE-2026-109619"],
                "limitations": "Affected versions are not yet known.",
            },
            "records": [
                {
                    "id": "PHP-0037",
                    "name": "PHP core and Zend Engine",
                    "publisher": "The PHP Group",
                    "category": "PHP core",
                    "relationship": "component",
                    "relationship_direction": "part_of_php",
                    "evidence_summary": "Upstream PHP runtime.",
                    "cve_2026_109618": "PHP relationship confirmed; CVE match unknown",
                    "cve_2026_109619": "PHP relationship confirmed; CVE match unknown",
                },
                {
                    "id": "PHP-0001",
                    "name": "PHP-FPM",
                    "publisher": "The PHP Group",
                    "category": "Runtime interfaces",
                    "relationship": "bundles",
                    "relationship_direction": "part_of_php",
                    "parent_component": "PHP-0037",
                    "cve_2026_109618": "PHP relationship confirmed; CVE match unknown",
                    "cve_2026_109619": "PHP relationship confirmed; CVE match unknown",
                },
                {
                    "id": "PHP-0006",
                    "name": "WordPress",
                    "publisher": "WordPress",
                    "category": "CMS and publishing",
                    "relationship": "requires",
                    "relationship_direction": "depends_on_php",
                    "parent_component": "PHP-0037",
                    "cve_2026_109618": "PHP relationship confirmed; CVE match unknown",
                    "cve_2026_109619": "PHP relationship confirmed; CVE match unknown",
                },
            ],
        }

    def test_builds_packages_relationships_and_vex(self):
        document = MODULE.build_spdx_document(
            self.inventory,
            "urn:php2shell:test",
            "php2shell project",
        )
        graph = document["@graph"]

        self.assertEqual(document["@context"], MODULE.SPDX_CONTEXT)
        creation_info = next(e for e in graph if e["type"] == "CreationInfo")
        self.assertEqual(creation_info["created"], "2026-10-21T10:15:16Z")
        self.assertEqual(sum(e["type"] == "software_Package" for e in graph), 3)
        self.assertEqual(sum(e["type"] == "Relationship" for e in graph), 2)
        self.assertEqual(sum(e["type"] == "security_Vulnerability" for e in graph), 2)
        self.assertEqual(
            sum(e["type"] == "security_VexUnderInvestigationVulnAssessmentRelationship" for e in graph),
            2,
        )

        relationships = [e for e in graph if e["type"] == "Relationship"]
        self.assertIn(
            {
                "from": "urn:php2shell:test:package:PHP-0037",
                "to": ["urn:php2shell:test:package:PHP-0001"],
                "relationshipType": "contains",
            },
            [
                {
                    "from": rel["from"],
                    "to": rel["to"],
                    "relationshipType": rel["relationshipType"],
                }
                for rel in relationships
            ],
        )
        self.assertIn(
            {
                "from": "urn:php2shell:test:package:PHP-0006",
                "to": ["urn:php2shell:test:package:PHP-0037"],
                "relationshipType": "dependsOn",
            },
            [
                {
                    "from": rel["from"],
                    "to": rel["to"],
                    "relationshipType": rel["relationshipType"],
                }
                for rel in relationships
            ],
        )

    def test_rejects_duplicate_record_ids(self):
        self.inventory["records"].append(dict(self.inventory["records"][0]))
        with self.assertRaises(MODULE.ConversionError):
            MODULE.build_spdx_document(self.inventory, "urn:php2shell:test", "php2shell project")

    def test_reports_unresolved_parent_records(self):
        self.inventory["records"][1]["parent_component"] = "PHP core label only"
        unresolved = MODULE.unresolved_parent_records(self.inventory["records"])
        self.assertEqual([record["id"] for record in unresolved], ["PHP-0001"])

    def test_join_uri_supports_http_namespaces(self):
        self.assertEqual(
            MODULE.join_uri("https://example.test/spdx/", "package", "PHP-0001"),
            "https://example.test/spdx/package/PHP-0001",
        )


if __name__ == "__main__":
    unittest.main()
