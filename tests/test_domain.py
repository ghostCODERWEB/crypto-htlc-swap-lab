import unittest, copy, json
from decimal import Decimal
from pathlib import Path
from cryptolab import analyze
from cryptolab.engine import *

EXAMPLE = json.loads(Path("examples/input.json").read_text())


class DomainTests(unittest.TestCase):
    def test_swap_settlement(self):
        r = analyze(EXAMPLE)
        self.assertEqual(r["chains"]["chainA"]["balances"]["bob"], 50)
        self.assertTrue(r["swap_safety"][0]["safe_configuration"])

    def test_wrong_preimage(self):
        d = copy.deepcopy(EXAMPLE)
        d["events"][2]["preimage_hex"] = "00"
        with self.assertRaises(ValueError):
            analyze(d)

    def test_expiry_redemption(self):
        d = copy.deepcopy(EXAMPLE)
        d["events"] = d["events"][:3]
        d["events"][2]["timestamp"] = 60
        with self.assertRaises(ValueError):
            analyze(d)

    def test_refund(self):
        d = copy.deepcopy(EXAMPLE)
        d["swaps"] = []
        d["events"] = d["events"][:1] + [
            {
                "type": "refund",
                "chain": "chainA",
                "id": "a",
                "actor": "alice",
                "timestamp": 100,
            }
        ]
        self.assertEqual(analyze(d)["chains"]["chainA"]["balances"]["alice"], 100)

    def test_repeat_redeem(self):
        d = copy.deepcopy(EXAMPLE)
        d["events"].append({**d["events"][-1], "timestamp": 5})
        with self.assertRaises(ValueError):
            analyze(d)
