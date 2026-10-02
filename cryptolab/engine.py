"""Replay hash-locked escrow swaps with strict expiry rules, refunds and cross-leg safety analysis."""

import hashlib, copy
from .validation import identifier, integer, chronological


class Escrow:
    def __init__(self, balances):
        self.balances = {identifier(k): integer(v) for k, v in balances.items()}
        self.locks = {}
        self.total = sum(self.balances.values())

    def apply(self, e):
        kind = e["type"]
        time = e["timestamp"]
        key = identifier(e["id"])
        if kind == "lock":
            if key in self.locks:
                raise ValueError("duplicate lock")
            sender = identifier(e["sender"])
            recipient = identifier(e["recipient"])
            amount = integer(e["amount"], minimum=1)
            expiry = integer(e["expiry"])
            digest = e["hashlock"]
            if expiry <= time or len(digest) != 64:
                raise ValueError("invalid expiry or hashlock")
            try:
                bytes.fromhex(digest)
            except ValueError:
                raise ValueError("invalid hashlock")
            if sender not in self.balances or self.balances[sender] < amount:
                raise ValueError("insufficient escrow funds")
            self.balances[sender] -= amount
            self.locks[key] = {
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
                "expiry": expiry,
                "hashlock": digest.lower(),
                "status": "locked",
            }
        elif kind in ("redeem", "refund"):
            lock = self.locks[key]
            if lock["status"] != "locked":
                raise ValueError("escrow already settled")
            actor = identifier(e["actor"])
            if kind == "redeem":
                secret = bytes.fromhex(e["preimage_hex"])
                if (
                    time >= lock["expiry"]
                    or actor != lock["recipient"]
                    or hashlib.sha256(secret).hexdigest() != lock["hashlock"]
                ):
                    raise ValueError("invalid redemption")
                payee = lock["recipient"]
                lock["status"] = "redeemed"
                lock["preimage_hex"] = secret.hex()
            else:
                if time < lock["expiry"] or actor != lock["sender"]:
                    raise ValueError("invalid refund")
                payee = lock["sender"]
                lock["status"] = "refunded"
            self.balances[payee] = self.balances.get(payee, 0) + lock["amount"]
        else:
            raise ValueError("unknown escrow event")
        locked = sum(
            v["amount"] for v in self.locks.values() if v["status"] == "locked"
        )
        if sum(self.balances.values()) + locked != self.total:
            raise ValueError("escrow conservation failed")
        return {"type": kind, "id": key, "status": self.locks[key]["status"]}


def analyze(data):
    chains = {name: Escrow(balances) for name, balances in data["chains"].items()}
    events = []
    for e in chronological(data["events"]):
        events.append({"chain": e["chain"], **chains[e["chain"]].apply(e)})
    safety = []
    margin = integer(data.get("refund_safety_margin", 10))
    for swap in data.get("swaps", []):
        long = chains[swap["long_chain"]].locks[swap["long_lock"]]
        short = chains[swap["short_chain"]].locks[swap["short_lock"]]
        safe = (
            long["hashlock"] == short["hashlock"]
            and long["expiry"] - short["expiry"] >= margin
            and long["sender"] == short["recipient"]
            and long["recipient"] == short["sender"]
        )
        safety.append(
            {
                "id": swap["id"],
                "safe_configuration": safe,
                "expiry_gap": long["expiry"] - short["expiry"],
                "hashes_match": long["hashlock"] == short["hashlock"],
            }
        )
    return {
        "chains": {
            k: {
                "balances": copy.deepcopy(v.balances),
                "locks": copy.deepcopy(v.locks),
                "conserved_total": v.total,
            }
            for k, v in chains.items()
        },
        "events": events,
        "swap_safety": safety,
    }
