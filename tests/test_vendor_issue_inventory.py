import unittest
from pathlib import Path

from tools import build_spdx_inventory as compiler
from tools import generate_software_list_from_spdx3 as generator


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "urn:php2shell:inventory:"
CVES = ["CVE-2026-109618", "CVE-2026-109619"]


class VendorIssueInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document, _, _ = compiler.compile_inventory(ROOT / "software" / "spdx")
        cls.nodes = {node.get("spdxId", node.get("@id")): node
                     for node in cls.document["@graph"]}
        _, cls.entries = generator.build_entry_map(cls.document)

    def test_clearpass_partial_mitigations_are_not_full_fixes(self):
        product = self.entries[PREFIX + "package:PHP-0751"]
        self.assertEqual([product[cve] for cve in CVES], ["Vulnerable", "Vulnerable"])
        for version in ("6.14.0", "6.11.15", "6.14.1", "6.11.16"):
            self.assertIn(version, product["version"])
        self.assertIn("cluster-admin", product["notes"])
        self.assertIn("full fixes remain in development", product["notes"])
        self.assertIn("hpesbnw05171en_us", product["links"])

    def test_ontap_keeps_distinct_cve_assessments(self):
        product = self.entries[PREFIX + "package:PHP-0752"]
        self.assertEqual([product[cve] for cve in CVES], ["Vulnerable", "Not vuln"])
        self.assertEqual(generator.combined_status(product, CVES), "Vulnerable/Not vuln")
        self.assertIn("PHP jail", product["notes"])
        self.assertIn("No fixed release is listed", product["notes"])
        self.assertIn("NTAP-20261021-0021", product["links"])
        vex = self.nodes[PREFIX + "vex:CVE-2026-109618:affects:php-0752-official-20261023"]
        self.assertIn("authenticated attackers remain a risk", vex["security_actionStatement"])
        self.assertIn("repeat for new SVMs", vex["security_actionStatement"])

    def test_new_products_have_unique_identity_and_php_dependencies(self):
        for identifier, supplier, name in (
            ("PHP-0751", "Hewlett Packard Enterprise", "HPE Networking ClearPass Policy Manager"),
            ("PHP-0752", "NetApp", "ONTAP 9"),
        ):
            with self.subTest(identifier=identifier):
                matches = [entry for entry in self.entries.values()
                           if entry["supplier"] == supplier and entry["product"] == name]
                self.assertEqual(len(matches), 1)
                relationship = self.nodes[PREFIX + "relationship:" + identifier]
                self.assertEqual(relationship["from"], PREFIX + "package:" + identifier)
                self.assertEqual(relationship["relationshipType"], "dependsOn")
                self.assertEqual(relationship["to"], [PREFIX + "package:PHP-0037"])


if __name__ == "__main__":
    unittest.main()
