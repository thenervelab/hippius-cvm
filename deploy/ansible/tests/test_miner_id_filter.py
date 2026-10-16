"""Unit tests for the `node_id_to_miner_id` Ansible filter.

Run: python3 deploy/ansible/tests/test_miner_id_filter.py
(stdlib only — no Ansible install needed).
"""

import importlib.util
import pathlib
import unittest

_PLUGIN = (
    pathlib.Path(__file__).resolve().parent.parent
    / "playbooks"
    / "filter_plugins"
    / "miner_id.py"
)
_spec = importlib.util.spec_from_file_location("miner_id_filter", _PLUGIN)
assert _spec is not None and _spec.loader is not None
miner_id_filter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(miner_id_filter)
node_id_to_miner_id = miner_id_filter.node_id_to_miner_id

NODE_ID = "0123456789abcdef" + "fedcba9876543210" * 3


class NodeIdToMinerIdTest(unittest.TestCase):
    def test_prefix_plus_first_16_hex(self) -> None:
        self.assertEqual(node_id_to_miner_id(NODE_ID), "m-0123456789abcdef")

    def test_fits_vali_miner_id_bound(self) -> None:
        # vali `MinerIdentity.miner_id` and the heartbeat body cap at 64.
        self.assertEqual(len(node_id_to_miner_id(NODE_ID)), 18)

    def test_uppercase_is_lowercased(self) -> None:
        self.assertEqual(node_id_to_miner_id(NODE_ID.upper()), "m-0123456789abcdef")

    def test_surrounding_whitespace_ignored(self) -> None:
        self.assertEqual(node_id_to_miner_id(f"  {NODE_ID}\n"), "m-0123456789abcdef")

    def test_registered_as_filter(self) -> None:
        filters = miner_id_filter.FilterModule().filters()
        self.assertIs(filters["node_id_to_miner_id"], node_id_to_miner_id)

    def test_malformed_rejected(self) -> None:
        for bad in (
            "",
            NODE_ID[:63],
            NODE_ID + "0",
            "0x" + NODE_ID[:62],
            "g" + NODE_ID[1:],
            NODE_ID[:32] + " " + NODE_ID[33:],
            "-----BEGIN PUBLIC KEY-----",
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                node_id_to_miner_id(bad)

    def test_non_string_rejected(self) -> None:
        with self.assertRaises(ValueError):
            node_id_to_miner_id(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
