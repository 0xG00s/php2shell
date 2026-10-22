import json
from pathlib import Path
import unittest


INVENTORY = Path(__file__).resolve().parents[1] / "software/spdx/PHP_Downstream_Inventory.spdx3.json"
PREFIX = "urn:php2shell:inventory:"
FORTINET = PREFIX + "organization:fortinet:0dd4907ae878"


class InventoryIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = json.loads(INVENTORY.read_text(encoding="utf-8"))["@graph"]
        cls.index = {node["spdxId"]: node for node in cls.graph if "spdxId" in node}

    def test_unique_ids_and_resolved_internal_references(self):
        ids = [node["spdxId"] for node in self.graph if "spdxId" in node]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate SPDX IDs")
        for node in self.graph:
            for key in ("from", "to", "element", "rootElement", "suppliedBy"):
                values = node.get(key, [])
                if isinstance(values, str):
                    values = [values]
                for value in values:
                    if value.startswith(PREFIX):
                        with self.subTest(node=node.get("spdxId"), field=key, reference=value):
                            self.assertIn(value, self.index)
        elements = self.index[PREFIX + "bundle"]["element"]
        self.assertEqual(len(elements), len(set(elements)), "Duplicate bundle members")

    def test_colliding_product_ids_remain_distinct(self):
        expected = {"PHP-0676": "Check Point firewall web interfaces", "PHP-0725": "FortiADC Manager"}
        for record_id, name in expected.items():
            with self.subTest(record_id=record_id):
                package_id = PREFIX + "package:" + record_id
                package = self.index[package_id]
                self.assertEqual(package["name"], name)
                self.assertIn(record_id, [item["identifier"] for item in package["externalIdentifier"]])
                relationship = self.index[PREFIX + "relationship:" + record_id]
                self.assertEqual(relationship["from"], package_id)
                self.assertIn(package_id, self.index[PREFIX + "bundle"]["element"])

    def test_fortinet_candidates_do_not_assert_confirmed_php_dependency(self):
        candidates = [node for node in self.graph if node.get("suppliedBy") == FORTINET
                      and "Evidence status: Vendor advisory candidate" in node.get("comment", "")]
        self.assertTrue(candidates)
        for package in candidates:
            with self.subTest(product=package["name"]):
                relationships = [node for node in self.graph if node.get("type") == "Relationship"
                                 and node.get("from") == package["spdxId"]
                                 and PREFIX + "package:PHP-0037" in node.get("to", [])]
                self.assertEqual(len(relationships), 1)
                self.assertEqual(relationships[0]["relationshipType"], "other")
                self.assertIn("Relationship direction: unconfirmed", package["comment"])

    def test_each_fortinet_product_has_one_assessment_per_cve(self):
        packages = [node for node in self.graph if node.get("suppliedBy") == FORTINET]
        self.assertTrue(packages)
        for package in packages:
            for cve in ("CVE-2026-109618", "CVE-2026-109619"):
                with self.subTest(product=package["name"], cve=cve):
                    assessments = [node for node in self.graph
                                   if node.get("type", "").startswith("security_Vex")
                                   and node.get("from") == PREFIX + "vulnerability:" + cve
                                   and package["spdxId"] in node.get("to", [])]
                    self.assertEqual(len(assessments), 1)


if __name__ == "__main__":
    unittest.main()
